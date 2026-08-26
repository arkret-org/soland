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

use arkret_identifiers::{Hash, RealmId};
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_models_crypto::{
    Failure as KeypackageFailure, KeyOperationSignature, KeyPackageClaimRecord,
    KeyPackageClaimTerminalReceipt, KeyPackageClaimTerminalState, KeyPackageConsumeReceipt,
    KeyPackageUploadEntry, KeyPackagesClaimOutcome, KeyPackagesClaimRequestBody,
    KeyPackagesConsumeOutcome, KeyPackagesConsumeRequestBody, KeyPackagesRevokeOutcome,
    KeyPackagesRevokeRequestBody, KeyPackagesUploadOutcome, KeyPackagesUploadRequestBody,
    PeerKeyPackageClaimErrorCode, PeerKeyPackageClaimPurpose, PeerKeyPackageClaimReceipt,
    PeerKeyPackageRequesterAuthorization, PeerKeyPackagesClaimOutcome,
    PeerKeyPackagesClaimQueryOutcome, PeerKeyPackagesClaimQueryRequestBody,
    PeerKeyPackagesClaimQueryState, PeerKeyPackagesClaimRequestBody,
    keypackage_claim_authorization_signing_bytes, peer_keypackage_claim_receipt_signing_bytes,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::Signer as _;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::Value;
use soland_domain::reducer::mls::KeyPackageTrustBinding;
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

/// Canonical MLS event-payload field readers shared by every surface that
/// inspects a raw `ak.mls.*` payload (submit preflight, projection mirroring,
/// sync visibility, sidecar binding, MIMI interop, circle scope rotation).
#[path = "mls_payload_fields.rs"]
pub(crate) mod payload_fields;

const LAST_RESORT_KEYPACKAGE_MAX_LIFETIME_SECS: i64 = 30 * 24 * 60 * 60;

fn welcome_recipient_device_id(
    welcome: &arkret_models_collaboration::events_payloads::MlsWelcomePayload,
) -> Option<&arkret_wire::DeviceId> {
    match &welcome.recipient {
        arkret_models_collaboration::events_payloads::MlsWelcomeRecipient::Device {
            recipient_device_id,
        } => Some(recipient_device_id),
        arkret_models_collaboration::events_payloads::MlsWelcomeRecipient::NativeAgent {
            ..
        }
        | arkret_models_collaboration::events_payloads::MlsWelcomeRecipient::MinimalMetadataPairwise { .. } => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum KeyPackageTrustSelector {
    Principal(KeyPackageTrustBinding),
    PerDevice(BTreeMap<String, KeyPackageTrustBinding>),
    MinimalMetadataPairwise {
        verification_method: String,
        intended_realm_id: String,
    },
}

/// Lift the reducer's exactly-one-of validation into this layer's error type.
/// The reducer owns the rule and the `claim_generation_mismatch` reason code;
/// only the operator-facing message differs per call site.
fn trust_binding_from_parts(
    device_authorize_event_id: Option<String>,
    agent_key_authorize_event_id: Option<String>,
    pairwise_actor_id: Option<String>,
    pairwise_verification_method: Option<String>,
    message: &'static str,
) -> Result<KeyPackageTrustBinding, AppError> {
    KeyPackageTrustBinding::from_parts(
        device_authorize_event_id,
        agent_key_authorize_event_id,
        pairwise_actor_id,
        pairwise_verification_method,
    )
    .map_err(|reason_code| {
        AppError::new(ErrorCode::FailedPrecondition, message).with_wire_code(reason_code)
    })
}

fn trust_binding_from_keypackage(
    kp: &MlsKeyPackageRow,
) -> Result<KeyPackageTrustBinding, AppError> {
    trust_binding_from_parts(
        kp.device_authorize_event_id.clone(),
        kp.agent_key_authorize_event_id.clone(),
        (kp.device_authorize_event_id.is_none() && kp.agent_key_authorize_event_id.is_none())
            .then(|| kp.actor_id.clone()),
        kp.endpoint_verification_method.clone(),
        "KeyPackage trust binding is invalid",
    )
}

fn trust_binding_from_row(row: &MlsKeyPackageRow) -> Result<KeyPackageTrustBinding, AppError> {
    trust_binding_from_parts(
        row.device_authorize_event_id.clone(),
        row.agent_key_authorize_event_id.clone(),
        (row.device_authorize_event_id.is_none() && row.agent_key_authorize_event_id.is_none())
            .then(|| row.actor_id.clone()),
        row.endpoint_verification_method.clone(),
        "KeyPackage claim is missing a valid trust binding",
    )
}

fn trust_binding_matches_keypackage(
    binding: &KeyPackageTrustBinding,
    kp: &MlsKeyPackageRow,
) -> bool {
    kp.device_authorize_event_id == binding.device_authorize_event_id
        && kp.agent_key_authorize_event_id == binding.agent_key_authorize_event_id
        && binding
            .pairwise_actor_id
            .as_ref()
            .is_none_or(|actor_id| actor_id == &kp.actor_id)
        && binding
            .pairwise_verification_method
            .as_deref()
            .is_none_or(|method| kp.endpoint_verification_method.as_deref() == Some(method))
}

impl KeyPackageTrustSelector {
    fn matches_keypackage(&self, kp: &MlsKeyPackageRow) -> bool {
        match self {
            Self::Principal(binding) => trust_binding_matches_keypackage(binding, kp),
            Self::PerDevice(bindings) => bindings
                .get(kp.device_id.as_deref().unwrap_or(""))
                .is_some_and(|binding| trust_binding_matches_keypackage(binding, kp)),
            Self::MinimalMetadataPairwise {
                verification_method,
                intended_realm_id,
            } => {
                kp.device_id.is_none()
                    && kp.device_authorize_event_id.is_none()
                    && kp.agent_key_authorize_event_id.is_none()
                    && kp.endpoint_verification_method.as_deref() == Some(verification_method)
                    && kp.intended_realm_id.as_deref() == Some(intended_realm_id)
            }
        }
    }
}

/// Mount the `/keys/keypackages/*` sub-router. Mounted under
/// `/_arkret/self` from `routing::mod::arkret_protocol_router`.
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
    body.validate_shape().map_err(AppError::param_invalid)?;
    let principal_id = body.principal_id.clone();
    let actor_id = body.principal_id.to_string();
    if body.pairwise_verification_method.is_none() && actor_id != session.actor {
        return Err(AppError::capability_denied(
            "actor_id must match the calling session",
        ));
    }
    if body.keypackages.is_empty() {
        return Err(AppError::param_missing("keypackages is required"));
    }
    let (device_id, trust_binding, publish_trust_anchor) = if let Some(device_id) = &body.device_id
    {
        if device_id.as_str() != session.device_id {
            return Err(AppError::capability_denied(
                "device_id must match the calling session",
            ));
        }
        let binding =
            current_keypackage_trust_binding(state, &principal_id, device_id.as_str()).await?;
        let anchor = match (
            binding.device_authorize_event_id.as_ref(),
            binding.agent_key_authorize_event_id.as_ref(),
        ) {
            (Some(event_id), None) => {
                soland_domain::reducer::mls::MlsKeyPackagePublishTrustAnchor::DeviceAuthorize(
                    event_id.clone(),
                )
            }
            _ => {
                return Err(AppError::param_invalid(
                    "device upload has no active device authorization",
                ));
            }
        };
        (Some(device_id.as_str().to_owned()), Some(binding), anchor)
    } else if let (Some(method), Some(event_id)) = (
        &body.agent_verification_method,
        &body.agent_key_authorize_event_id,
    ) {
        (
            None,
            Some(KeyPackageTrustBinding::agent_key_authorize(
                event_id.as_str().to_owned(),
            )),
            soland_domain::reducer::mls::MlsKeyPackagePublishTrustAnchor::AgentKeyAuthorize {
                event_id: event_id.as_str().to_owned(),
                verification_method: method.as_str().to_owned(),
            },
        )
    } else {
        let method = body
            .pairwise_verification_method
            .as_ref()
            .expect("validated pairwise method");
        let realm_id = body
            .intended_realm_id
            .as_ref()
            .expect("validated pairwise Realm");
        ensure_pairwise_realm_affinity(state, &principal_id, method, realm_id, state.service_id())
            .await?;
        (
            None,
            None,
            soland_domain::reducer::mls::MlsKeyPackagePublishTrustAnchor::MinimalMetadataPairwise {
                verification_method: method.as_str().to_owned(),
                intended_realm_id: realm_id.as_str().to_owned(),
            },
        )
    };
    let endpoint_device_id = device_id.as_deref();
    let unsigned_upload = body.unsigned();
    let upload_signing_input =
        arkret_models_crypto::http_bodies::keypackages_upload_signing_input(&unsigned_upload)
            .map_err(|error| {
                AppError::param_invalid(format!(
                    "KeyPackage upload canonical input failed: {error}"
                ))
            })?;
    if let Some(authorize_event_id) = trust_binding
        .as_ref()
        .and_then(|binding| binding.agent_key_authorize_event_id.as_deref())
    {
        verify_agent_keypackage_batch(
            state,
            &principal_id,
            authorize_event_id,
            &body.endpoint_signature,
            &upload_signing_input,
        )
        .await
        .map_err(AppError::param_invalid)?;
    } else if device_id.is_some() {
        verify_device_keypackage_signature(
            state,
            &principal_id,
            endpoint_device_id.expect("validated device upload has a device id"),
            &body.endpoint_signature,
            &upload_signing_input,
        )
        .await?;
    } else {
        let method = body
            .pairwise_verification_method
            .as_ref()
            .expect("validated pairwise method");
        verify_pairwise_keypackage_batch(
            &principal_id,
            method,
            &body.endpoint_signature,
            &upload_signing_input,
        )
        .map_err(AppError::param_invalid)?;
    }

    let mut accepted = 0_u32;
    let mut key_package_refs = Vec::new();
    let mut rejected = Vec::new();
    for entry in body.keypackages {
        if entry.keypackage_id.is_empty() {
            rejected.push(keypackage_failure(
                &entry,
                endpoint_device_id,
                "keypackage_id_missing",
            ));
            continue;
        }
        let keypackage_id = entry.keypackage_id.clone();
        if entry.keypackage_ref.is_empty() {
            rejected.push(keypackage_failure(
                &entry,
                endpoint_device_id,
                "keypackage_ref_missing",
            ));
            continue;
        }
        let keypackage_ref = entry.keypackage_ref.clone();
        let key_package_bytes_b64 = entry.keypackage.to_string();
        let key_package_bytes = match decode_key_package(&key_package_bytes_b64) {
            Ok(bytes) => bytes,
            Err(reason) => {
                rejected.push(keypackage_failure(&entry, endpoint_device_id, reason));
                continue;
            }
        };
        let keypackage_digest = arkret_canonical::sha256_digest(&key_package_bytes);
        let capabilities = match validate_capabilities(&entry.capabilities) {
            Ok(value) => value,
            Err(reason) => {
                rejected.push(keypackage_failure(&entry, endpoint_device_id, reason));
                continue;
            }
        };
        if arkret_mls::validate_keypackage_capability_binding(&key_package_bytes, &capabilities)
            .is_err()
        {
            rejected.push(keypackage_failure(
                &entry,
                endpoint_device_id,
                "keypackage_capabilities_signed_binding_invalid",
            ));
            continue;
        }
        if let Some(authorize_event_id) = trust_binding
            .as_ref()
            .and_then(|binding| binding.agent_key_authorize_event_id.as_deref())
            && let Err(reason) = validate_agent_keypackage_leaf(
                state,
                &principal_id,
                authorize_event_id,
                &key_package_bytes,
            )
            .await
        {
            rejected.push(keypackage_failure(&entry, endpoint_device_id, reason));
            continue;
        }
        if let Some(endpoint_device_id) = endpoint_device_id
            && let Err(reason) = validate_device_keypackage_leaf(
                state,
                &principal_id,
                endpoint_device_id,
                &key_package_bytes,
            )
            .await
        {
            rejected.push(keypackage_failure(&entry, Some(endpoint_device_id), reason));
            continue;
        }
        if device_id.is_none() && trust_binding.is_none() {
            let method = body
                .pairwise_verification_method
                .as_ref()
                .expect("validated pairwise method");
            if let Err(reason) =
                validate_pairwise_keypackage_leaf(&principal_id, method, &key_package_bytes)
            {
                rejected.push(keypackage_failure(&entry, endpoint_device_id, reason));
                continue;
            }
        }
        let created_at = entry.created_at.timestamp();
        let expires_at = entry.expires_at.timestamp();
        let last_resort = entry.last_resort.unwrap_or(false);
        if last_resort
            && expires_at.saturating_sub(created_at) > LAST_RESORT_KEYPACKAGE_MAX_LIFETIME_SECS
        {
            rejected.push(keypackage_failure(
                &entry,
                endpoint_device_id,
                "last_resort_keypackage_lifetime_too_long",
            ));
            continue;
        }

        // KeyPackage upload is a local HTTP/storage workflow, not an accepted
        // Event. Keep its reducer input typed instead of manufacturing a
        // `ProjectedEventOperation` with a synthetic Event identity.
        let trust_anchor = publish_trust_anchor.clone();
        let projection = soland_domain::reducer::mls::MlsKeyPackagePublishProjection {
            keypackage_id: keypackage_id.clone(),
            keypackage_ref: keypackage_ref.clone(),
            keypackage_digest,
            actor_id: actor_id.clone(),
            device_id: device_id.clone(),
            lifetime: soland_domain::reducer::KeyPackageLifetimeProjection {
                not_before: created_at,
                not_after: expires_at,
            },
            key_package_bytes,
            capabilities,
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
                rejected.push(keypackage_failure(&entry, endpoint_device_id, reason));
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
        let _attached = state
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
        .map_err(|_| AppError::json_invalid("invalid peer KeyPackage claim request body"))?;
    // Service authentication is deliberately first so an unauthenticated
    // caller cannot probe whether a target principal or KeyPackage exists.
    crate::routing::events::peer::validate_peer_request(state, req, true).await?;
    let transport = peer_claim_transport_binding(state, req)?;
    if body.service_binding.source_service_id != transport.source_service_id
        || body.service_binding.destination_service_id != transport.destination_service_id
    {
        return Err(peer_claim_schema_violation(
            "request service_binding must equal the authenticated HTTP service coordinates",
        ));
    }
    let claim_request_id = body.claim_request_id.as_str();
    if peer_required_header(req, "idempotency-key")? != claim_request_id {
        return Err(peer_claim_schema_violation(
            "Idempotency-Key must equal claim_request_id",
        ));
    }
    body.validate_shape()
        .map_err(|error| peer_claim_schema_violation(error.to_string()))?;
    validate_peer_claim_time_window(&body)?;

    claim_keypackage_at_destination(state, &body).await
}

async fn claim_keypackage_at_destination(
    state: &AppState,
    body: &PeerKeyPackagesClaimRequestBody,
) -> JsonResult<PeerKeyPackagesClaimOutcome> {
    let body_value = serde_json::to_value(body)
        .map_err(|error| AppError::internal(format!("KeyPackage claim serialize: {error}")))?;
    let source_service_id = body.service_binding.source_service_id.as_str().to_owned();
    let claim_request_id = body.claim_request_id.as_str();
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
        record_peer_claim_failed(state, body, &source_service_id, &request_digest).await?;
        return Err(peer_claim_failed());
    }

    let policy_authorized = peer_claim_policy_authorized(state, body, &source_service_id).await?;
    let participant_authorized = if policy_authorized {
        verify_peer_claim_participant_authorization(state, body).await?
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
        record_peer_claim_failed(state, body, &source_service_id, &request_digest).await?;
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
    let target_keypackage_ref = body
        .target_keypackage_ref
        .as_ref()
        .map(|reference| reference.as_str());
    let trust_selector = current_keypackage_claim_trust_selector(
        state,
        &body.target_principal_id,
        &target_device_ids,
        Some(body.intended_realm_id.as_str()),
        body.target_pairwise_verification_method
            .as_ref()
            .map(|method| method.as_str()),
    )
    .await
    .map_err(|_| peer_claim_failed())?;
    let now_unix_ms = now().timestamp_millis();
    let now_secs = now_unix_ms.div_euclid(1000);
    let candidate_ids = {
        let keypackages = state.projections().mls_key_package_records();
        let mut candidates = keypackages
            .iter()
            .filter_map(|keypackage| {
                if ordinary_keypackage_is_available(keypackage) {
                    Some((0_u8, keypackage))
                } else if body.last_resort_allowed == Some(true)
                    && last_resort_matches_realm(keypackage, body.intended_realm_id.as_str())
                {
                    Some((1_u8, keypackage))
                } else {
                    None
                }
            })
            .filter(|(_, keypackage)| {
                target_keypackage_ref.is_none_or(|expected| keypackage.keypackage_ref == expected)
            })
            .filter(|(_, keypackage)| {
                keypackage.lifetime_not_after.saturating_mul(1000)
                    >= body.expires_at.timestamp_millis()
            })
            .filter(|(_, keypackage)| {
                keypackage_matches_claim(
                    keypackage,
                    target_principal_id,
                    &target_device_ids,
                    &trust_selector,
                    now_secs,
                    &required_capabilities,
                )
            })
            .map(|(priority, keypackage)| {
                (
                    priority,
                    keypackage.created_at,
                    keypackage.id.clone(),
                    trust_binding_from_keypackage(keypackage),
                )
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            (&left.0, &left.1, &left.2).cmp(&(&right.0, &right.1, &right.2))
        });
        candidates
    };

    for (priority, _, candidate_id, binding) in candidate_ids {
        let binding = binding.map_err(|_| peer_claim_failed())?;
        let Some(mut predicted) = state
            .mls_key_packages()
            .key_package(&candidate_id)
            .await
            .map_err(|error| AppError::internal(format!("peer claim candidate lookup: {error}")))?
        else {
            continue;
        };
        if target_keypackage_ref
            .is_some_and(|expected| predicted.keypackage_ref.as_str() != expected)
        {
            continue;
        }
        let is_last_resort = priority == 1;
        if if is_last_resort {
            body.last_resort_allowed != Some(true)
                || !last_resort_matches_realm(&predicted, body.intended_realm_id.as_str())
        } else {
            !ordinary_keypackage_is_available(&predicted)
        } {
            continue;
        }
        if !is_last_resort {
            predicted.claimed_by_mls_group_id = Some(body.mls_group_id.as_str().to_owned());
            predicted.claimed_at = Some(now_secs);
            predicted.claim_expires_at_unix_ms = Some(body.expires_at.timestamp_millis());
            predicted.consumed_at = None;
        }
        let outcome =
            build_peer_claim_outcome(state, body, &source_service_id, &request_digest, &predicted)
                .await?;
        let outcome_value = serde_json::to_value(&outcome).map_err(|error| {
            AppError::internal(format!("peer claim outcome serialize: {error}"))
        })?;
        let ledger = PeerKeyPackageClaimLedgerRecord {
            source_service_id: source_service_id.clone(),
            claim_request_id: claim_request_id.to_owned(),
            request_digest: request_digest.clone(),
            key_package_use: if is_last_resort {
                "last_resort"
            } else {
                "single_use"
            }
            .to_owned(),
            state: if is_last_resort {
                "last_resort_claimed"
            } else {
                "claimed"
            }
            .to_owned(),
            outcome: Some(outcome_value),
            consume_receipt: None,
            terminal_receipt: None,
            keypackage_id: Some(candidate_id.clone()),
            claim_expires_at_unix_ms: Some(body.expires_at.timestamp_millis()),
            expires_at: (body.expires_at + chrono::Duration::minutes(10)).timestamp(),
            updated_at: now_secs,
        };
        let device_revocation_gate = if binding.device_authorize_event_id.is_some() {
            let Some(predicted_device_id) = predicted.device_id.as_deref() else {
                continue;
            };
            match keypackage_device_revocation_gate(
                state,
                &predicted.actor_id,
                predicted_device_id,
                binding.device_authorize_event_id.as_deref(),
            )
            .await
            {
                Ok(selector) => selector,
                Err(_) => continue,
            }
        } else {
            None
        };
        match state
            .mls_key_packages()
            .claim_peer_key_package(PeerKeyPackageClaimAttempt {
                keypackage_id: &candidate_id,
                mls_group_id: body.mls_group_id.as_str(),
                device_authorize_event_id: binding.device_authorize_event_id.as_deref(),
                agent_key_authorize_event_id: binding.agent_key_authorize_event_id.as_deref(),
                device_revocation_gate: device_revocation_gate.as_ref(),
                claimed_at_unix_ms: now_unix_ms,
                claim_expires_at_unix_ms: body.expires_at.timestamp_millis(),
                ledger: &ledger,
            })
            .await
            .map_err(|error| AppError::internal(format!("peer KeyPackage CAS: {error}")))?
        {
            PeerKeyPackageClaimAttemptResult::Claimed(claimed) => {
                if !is_last_resort {
                    state.projections().mark_key_package_claimed(
                        &candidate_id,
                        body.mls_group_id.as_str().to_owned(),
                        now_secs,
                        Some(body.expires_at.timestamp_millis()),
                    );
                }
                debug_assert_eq!(claimed.id, candidate_id);
                return json_ok(outcome);
            }
            PeerKeyPackageClaimAttemptResult::Existing(existing) => {
                return replay_peer_claim(*existing, &request_digest);
            }
            PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable => continue,
        }
    }

    record_peer_claim_failed(state, body, &source_service_id, &request_digest).await?;
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
        .map_err(|_| AppError::json_invalid("invalid peer KeyPackage claim query body"))?;
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
        "claimed" | "last_resort_claimed" => (PeerKeyPackagesClaimQueryState::Claimed, None),
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
            arkret_wire::DidCoreId::new(source_service_id.clone()).map_err(|error| {
                AppError::internal(format!("peer source service id invalid: {error}"))
            })?,
            now(),
        )?;
        let receipt_value = serde_json::to_value(&receipt)
            .map_err(|error| AppError::internal(format!("terminal receipt serialize: {error}")))?;
        let _attached = state
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

#[derive(Debug)]
struct PeerClaimHttpTransportBinding {
    source_service_id: arkret_wire::DidCoreId,
    destination_service_id: arkret_wire::DidCoreId,
}

fn peer_claim_transport_binding(
    state: &AppState,
    req: &Request,
) -> Result<PeerClaimHttpTransportBinding, AppError> {
    let source_service_id =
        arkret_wire::DidCoreId::new(peer_required_header(req, "source-service-id")?)
            .map_err(|_| peer_claim_schema_violation("source-service-id must be a core_id"))?;
    let destination_service_id =
        arkret_wire::DidCoreId::new(peer_required_header(req, "destination-service-id")?)
            .map_err(|_| peer_claim_schema_violation("destination-service-id must be a core_id"))?;
    let source_trust_domain =
        arkret_identifiers::TrustDomainId::new(peer_required_header(req, "source-trust-domain")?)
            .map_err(|_| peer_claim_schema_violation("source-trust-domain is invalid"))?;
    let destination_trust_domain = arkret_identifiers::TrustDomainId::new(peer_required_header(
        req,
        "destination-trust-domain",
    )?)
    .map_err(|_| peer_claim_schema_violation("destination-trust-domain is invalid"))?;
    let local_trust_domain = state.config().trust_domain.clone();
    if destination_service_id.as_str() != state.service_id()
        || source_service_id == destination_service_id
        || source_trust_domain != local_trust_domain
        || destination_trust_domain != local_trust_domain
    {
        return Err(crate::routing::events::peer::cross_domain_replay(
            "peer KeyPackage claim transport binding does not target this service in the same trust domain",
        ));
    }
    Ok(PeerClaimHttpTransportBinding {
        source_service_id,
        destination_service_id,
    })
}

fn validate_peer_claim_time_window(body: &PeerKeyPackagesClaimRequestBody) -> Result<(), AppError> {
    let authorization = &body.requester_authorization;
    let signed_at = match authorization {
        PeerKeyPackageRequesterAuthorization::Device { signed_at, .. }
        | PeerKeyPackageRequesterAuthorization::NativeAgent { signed_at, .. }
        | PeerKeyPackageRequesterAuthorization::MinimalMetadataPairwise { signed_at, .. } => {
            *signed_at
        }
    };
    let current = now();
    if signed_at > current + chrono::Duration::seconds(60)
        || body.expires_at <= signed_at
        || body.expires_at.signed_duration_since(signed_at) > chrono::Duration::minutes(5)
        || body.expires_at <= current
    {
        return Err(peer_claim_schema_violation(
            "peer KeyPackage claim authorization time window is invalid",
        ));
    }
    Ok(())
}

fn verification_method_binds_core_device(
    verification_method: &arkret_wire::DidUrl,
    principal_id: &arkret_wire::DidCoreId,
    device_id: &arkret_wire::DeviceId,
) -> bool {
    let Some((controller, fragment)) = verification_method.rsplit_once('#') else {
        return false;
    };
    if fragment != device_id.as_str() {
        return false;
    }
    arkret_wire::DidFullId::new(controller.to_owned())
        .and_then(|full_id| arkret_wire::project_full_id_to_core_id(&full_id))
        .is_ok_and(|core| core == *principal_id)
}

async fn verify_peer_claim_participant_authorization(
    state: &AppState,
    body: &PeerKeyPackagesClaimRequestBody,
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
    if let PeerKeyPackageRequesterAuthorization::MinimalMetadataPairwise {
        verification_method,
        signature,
        ..
    } = authorization
    {
        if signature.kid.as_str() != verification_method.as_str()
            || signature
                .signature_algorithm
                .as_ref()
                .is_some_and(|algorithm| algorithm.as_str() != "Ed25519")
            || arkret_models_crypto::MlsEndpointIdentity::minimal_metadata_pairwise(
                body.requester.clone(),
                verification_method.clone(),
            )
            .is_err()
            || ensure_pairwise_realm_affinity(
                state,
                &body.requester,
                verification_method,
                &body.intended_realm_id,
                body.service_binding.source_service_id.as_str(),
            )
            .await
            .is_err()
        {
            return reject("minimal_metadata_pairwise_signature_shape");
        }
        let signing_bytes = keypackage_claim_authorization_signing_bytes(
            &body.unsigned_request(),
            &body.service_binding,
            authorization,
        )
        .map_err(|error| {
            AppError::internal(format!("peer claim authorization transcript: {error}"))
        })?;
        let key =
            crate::jws_verify::resolve_ed25519_pubkey_async(state, verification_method.as_str())
                .await
                .map_err(|error| AppError::internal(format!("pairwise signing key: {error}")))?;
        return Ok(crate::routing::identity::device_signing::ed25519_verify(
            &key,
            &signing_bytes,
            signature.sig.as_str(),
        ));
    }
    if let PeerKeyPackageRequesterAuthorization::NativeAgent {
        verification_method,
        requester_agent_id,
        agent_key_authorize_event_id,
        signature,
        ..
    } = authorization
    {
        let agent = state
            .agent_pairings()
            .agent(requester_agent_id.as_str())
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
        let Some(agent) = agent else {
            return reject("native_agent_missing");
        };
        if agent.state != AgentLifecycleState::Active
            || !current_agent_key_authorization_matches_method(
                state,
                requester_agent_id,
                agent_key_authorize_event_id.as_str(),
                verification_method.as_str(),
            )
            .await
            || requester_agent_id != &body.requester
        {
            return reject("native_agent_authorization_stale");
        }
        if signature
            .signature_algorithm
            .as_ref()
            .is_some_and(|algorithm| algorithm.as_str() != "Ed25519")
            || signature.kid.as_str() != verification_method.as_str()
        {
            return reject("native_agent_signature_shape");
        }
        let signing_bytes = keypackage_claim_authorization_signing_bytes(
            &body.unsigned_request(),
            &body.service_binding,
            authorization,
        )
        .map_err(|error| {
            AppError::internal(format!("peer claim authorization transcript: {error}"))
        })?;
        let key =
            crate::jws_verify::resolve_ed25519_pubkey_async(state, verification_method.as_str())
                .await
                .map_err(|error| AppError::internal(format!("Agent signing key: {error}")))?;
        return Ok(crate::routing::identity::device_signing::ed25519_verify(
            &key,
            &signing_bytes,
            signature.sig.as_str(),
        ));
    }
    let (verification_method, signature, requester_device_id, device_authorize_event_id) =
        match authorization {
            PeerKeyPackageRequesterAuthorization::Device {
                verification_method,
                requester_device_id,
                device_authorize_event_id,
                signature,
                ..
            } => (
                verification_method,
                signature,
                requester_device_id,
                device_authorize_event_id,
            ),
            PeerKeyPackageRequesterAuthorization::NativeAgent { .. } => unreachable!(),
            PeerKeyPackageRequesterAuthorization::MinimalMetadataPairwise { .. } => unreachable!(),
        };
    if signature
        .signature_algorithm
        .as_ref()
        .is_some_and(|algorithm| algorithm.as_str() != "Ed25519")
    {
        return reject("signature_algorithm");
    }
    let signing_bytes = keypackage_claim_authorization_signing_bytes(
        &body.unsigned_request(),
        &body.service_binding,
        authorization,
    )
    .map_err(|error| AppError::internal(format!("peer claim authorization transcript: {error}")))?;
    let key = {
        let device_id = requester_device_id;
        let facet =
            crate::routing::identity::device_signing::try_resolve_device_signing_directory_facet(
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
            != Some(device_authorize_event_id.as_str())
            || !verification_method_binds_core_device(
                verification_method,
                &body.requester,
                device_id,
            )
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
    };
    let signature_valid = crate::routing::identity::device_signing::ed25519_verify(
        &key,
        &signing_bytes,
        signature.sig.as_str(),
    );
    if !signature_valid {
        return reject("directory_governance_proof_signature_invalid");
    }
    Ok(true)
}

async fn peer_claim_policy_authorized(
    state: &AppState,
    body: &PeerKeyPackagesClaimRequestBody,
    source_service_id: &str,
) -> Result<bool, AppError> {
    let target_authority_current = if let Some(method) = &body.target_pairwise_verification_method {
        ensure_pairwise_realm_affinity(
            state,
            &body.target_principal_id,
            method,
            &body.intended_realm_id,
            state.service_id(),
        )
        .await
        .is_ok()
    } else if let (Some(agent_id), Some(method), Some(event_id)) = (
        &body.target_agent_id,
        &body.target_agent_verification_method,
        &body.target_agent_key_authorize_event_id,
    ) {
        agent_id == &body.target_principal_id
            && current_agent_key_authorization_matches_method(
                state,
                agent_id,
                event_id.as_str(),
                method.as_str(),
            )
            .await
    } else {
        state
            .identities()
            .account(body.target_principal_id.as_str())
            .await
            .map_err(|error| AppError::internal(format!("target authority lookup: {error}")))?
            .is_some()
    };
    if !target_authority_current {
        return Ok(false);
    }
    match body.claim_purpose {
        PeerKeyPackageClaimPurpose::RealmMembership => {
            if !crate::routing::federation::federation::federation_actor_origin_acceptable(
                state,
                body.requester.as_str(),
                source_service_id,
                None,
                body.intended_realm_id.as_str(),
                None,
            )
            .await
            {
                return Ok(false);
            }
            let projection = state.projections().snapshot();
            if projection
                .member(body.intended_realm_id.as_str(), body.requester.as_str())
                .filter(|member| member.state == "join")
                .and_then(|member| member.recipient_service_id.as_deref())
                != Some(source_service_id)
            {
                return Ok(false);
            }
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
            if contact.peer_service_id.as_deref() != Some(source_service_id) {
                return Ok(false);
            }
            let trust_domain = state.config().trust_domain.clone();
            let expected_pair_key = arkret_models_collaboration::objects::direct_conversation::direct_conversation_pair_key(
                trust_domain,
                arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant::unmapped(
                    body.requester.clone(),
                ),
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

async fn build_peer_claim_outcome(
    state: &AppState,
    body: &PeerKeyPackagesClaimRequestBody,
    source_service_id: &str,
    request_digest: &str,
    claimed: &MlsKeyPackageRow,
) -> Result<PeerKeyPackagesClaimOutcome, AppError> {
    let claims =
        vec![keypackage_claim_record(state, claimed, body.claim_request_id.as_str()).await?];
    let claims_value = serde_json::to_value(&claims)
        .map_err(|error| AppError::internal(format!("peer claim records serialize: {error}")))?;
    let claims_digest = arkret_canonical::canonical_sha256(&claims_value)
        .map_err(|error| AppError::internal(format!("peer claims digest: {error}")))?;
    let service_full_id = state.service_resolution_commitment().full_id.clone();
    let verification_method = format!("{service_full_id}#notary-key");
    let mut receipt = PeerKeyPackageClaimReceipt {
        claim_request_id: body.claim_request_id.clone(),
        request_digest: Hash::new(request_digest.to_owned())
            .map_err(|error| AppError::internal(format!("request digest invalid: {error}")))?,
        claims_digest: Hash::new(claims_digest)
            .map_err(|error| AppError::internal(format!("claims digest invalid: {error}")))?,
        source_service_id: arkret_wire::DidCoreId::new(source_service_id.to_owned())
            .map_err(|error| AppError::internal(format!("source service id invalid: {error}")))?,
        destination_service_id: arkret_wire::DidCoreId::new(state.service_id().clone())
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
    validate_welcome_peer_claim_ledger(
        state,
        source_service_id,
        Some(state.service_id()),
        realm_id,
        actor_id,
        payload,
    )
    .await
}

pub(in crate::routing) async fn validate_local_welcome_peer_claim(
    state: &AppState,
    realm_id: &str,
    actor_id: &str,
    payload: &Value,
) -> Result<(), &'static str> {
    validate_welcome_peer_claim_ledger(state, state.service_id(), None, realm_id, actor_id, payload)
        .await
}

async fn validate_welcome_peer_claim_ledger(
    state: &AppState,
    source_service_id: &str,
    required_destination_service_id: Option<&str>,
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
    let recipient_actor_id = match &welcome.recipient {
        arkret_models_collaboration::events_payloads::MlsWelcomeRecipient::Device {
            recipient_device_id,
        } => {
            let principal = welcome
                .recipient_principal_id
                .as_ref()
                .ok_or("peer_claim_welcome_invalid")?;
            let arkret_models_collaboration::events_payloads::MlsClaimTrustBinding::DeviceAuthorizeEventId(event_id) =
                &welcome.claim_ref.trust_binding
            else {
                return Err("peer_claim_welcome_invalid");
            };
            if !current_device_authorization_matches(
                state,
                principal,
                recipient_device_id.as_str(),
                event_id.as_str(),
            )
            .await
            {
                return Err("peer_claim_welcome_invalid");
            }
            principal
        }
        arkret_models_collaboration::events_payloads::MlsWelcomeRecipient::NativeAgent {
            recipient_agent_id,
            recipient_agent_verification_method,
            agent_key_authorize_event_id,
        } => {
            if welcome.recipient_principal_id.as_ref() != Some(recipient_agent_id)
                || !matches!(
                    &welcome.claim_ref.trust_binding,
                    arkret_models_collaboration::events_payloads::MlsClaimTrustBinding::AgentKeyAuthorizeEventId(claim_event_id)
                        if claim_event_id.as_str() == agent_key_authorize_event_id.as_str()
                )
                || !current_agent_key_authorization_matches_method(
                    state,
                    recipient_agent_id,
                    agent_key_authorize_event_id.as_str(),
                    recipient_agent_verification_method.as_str(),
                )
                .await
            {
                return Err("peer_claim_welcome_invalid");
            }
            recipient_agent_id
        }
        arkret_models_collaboration::events_payloads::MlsWelcomeRecipient::MinimalMetadataPairwise {
            recipient_pairwise_actor_id,
            recipient_pairwise_verification_method,
        } => {
            let realm = RealmId::new(realm_id.to_owned())
                .map_err(|_| "peer_claim_welcome_invalid")?;
            if welcome.recipient_principal_id.is_some()
                || ensure_pairwise_realm_affinity(
                    state,
                    recipient_pairwise_actor_id,
                    recipient_pairwise_verification_method,
                    &realm,
                    state.service_id(),
                )
                .await
                .is_err()
            {
                return Err("peer_claim_welcome_invalid");
            }
            recipient_pairwise_actor_id
        }
    };
    let receipt = &welcome.claim_receipt;
    let request = &receipt.request;
    if receipt.claim_request_id != request.claim_request_id
        || receipt.source_service_id.as_str() != source_service_id
        || required_destination_service_id
            .is_some_and(|expected| receipt.destination_service_id.as_str() != expected)
        || request.requester.as_str() != actor_id
        || &request.target_principal_id != recipient_actor_id
        || request.intended_realm_id.as_str() != realm_id
        || request.mls_group_id.as_str() != welcome.mls_group_id.as_str()
        || request.expires_at != receipt.expires_at
        || receipt.expires_at <= now()
        || welcome.claim_envelope.intended_realm_id != request.intended_realm_id
        || welcome.claim_envelope.requester_actor_id != request.requester
    {
        return Err("peer_claim_welcome_invalid");
    }
    if !receipt
        .signature
        .signature_algorithm
        .as_ref()
        .is_some_and(|algorithm| algorithm.as_str() == "Ed25519")
    {
        return Err("peer_claim_welcome_invalid");
    }
    let signing_bytes = peer_keypackage_claim_receipt_signing_bytes(receipt)
        .map_err(|_| "peer_claim_welcome_invalid")?;
    let verification_key = if receipt.destination_service_id.as_str() == state.service_id() {
        let expected_method = format!(
            "{}#notary-key",
            state.service_resolution_commitment().full_id
        );
        if receipt.signature.kid.as_str() != expected_method {
            return Err("peer_claim_welcome_invalid");
        }
        let resolution =
            crate::routing::system::service_resolution::current_authenticated_service_resolution(
                state,
            )
            .await
            .map_err(|_| "peer_claim_welcome_invalid")?;
        let document = arkret_identity::authenticated_service_document_at(
            &resolution,
            &receipt.destination_service_id,
            receipt.claimed_at,
        )
        .map_err(|_| "peer_claim_welcome_invalid")?;
        arkret_identity::jws::resolve_ed25519_pubkey_from_document(
            &document,
            receipt.signature.kid.as_str(),
        )
        .map_err(|_| "peer_claim_welcome_invalid")?
    } else {
        crate::jws_verify::validate_verification_method_controller(
            receipt.destination_service_id.as_str(),
            receipt.signature.kid.as_str(),
        )
        .map_err(|_| "peer_claim_welcome_invalid")?;
        crate::jws_verify::resolve_ed25519_pubkey_async(state, receipt.signature.kid.as_str())
            .await
            .map_err(|_| "peer_claim_welcome_invalid")?
    };
    if !crate::routing::identity::device_signing::ed25519_verify(
        &verification_key,
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
    if !peer_claim_state_allows_welcome(&ledger.state)
        || ledger.request_digest != receipt.request_digest.as_str()
    {
        return Err("peer_claim_welcome_invalid");
    }
    let outcome = ledger
        .outcome
        .and_then(|value| serde_json::from_value::<PeerKeyPackagesClaimOutcome>(value).ok())
        .ok_or("peer_claim_welcome_invalid")?;
    outcome
        .validate_shape()
        .map_err(|_| "peer_claim_welcome_invalid")?;
    if serde_json::to_value(&outcome.claim_receipt).ok() != serde_json::to_value(receipt).ok()
        || outcome.claims.len() != 1
    {
        return Err("peer_claim_welcome_invalid");
    }
    let claim = &outcome.claims[0];
    let claim_keypackage_bytes = URL_SAFE_NO_PAD
        .decode(claim.keypackage.as_bytes())
        .map_err(|_| "peer_claim_welcome_invalid")?;
    let claim_keypackage_digest = arkret_canonical::sha256_digest(&claim_keypackage_bytes);
    let claim_capabilities = arkret_canonical::canonical_json_bytes(&claim.capabilities)
        .map_err(|_| "peer_claim_welcome_invalid")?;
    let claim_capabilities_digest = arkret_canonical::sha256_digest(&claim_capabilities);
    if &claim.principal_id != recipient_actor_id
        || claim.device_id.as_ref() != welcome_recipient_device_id(&welcome)
        || claim.claim_id != welcome.claim_id.as_str()
        || claim.keypackage_ref != welcome.keypackage_ref
        || claim_keypackage_digest != welcome.claim_ref.keypackage_digest.as_str()
        || claim_capabilities_digest != welcome.claim_ref.capabilities_digest.as_str()
        || claim.expires_at < receipt.expires_at
    {
        return Err("peer_claim_welcome_invalid");
    }
    match (&welcome.recipient, &welcome.claim_ref.trust_binding) {
        (
            arkret_models_collaboration::events_payloads::MlsWelcomeRecipient::Device {
                recipient_device_id,
            },
            arkret_models_collaboration::events_payloads::MlsClaimTrustBinding::DeviceAuthorizeEventId(claim_ref_event_id),
        ) if claim.device_id.as_ref() == Some(recipient_device_id)
            && claim.device_authorize_event_id.as_ref().map(|id| id.as_str())
                == Some(claim_ref_event_id.as_str())
            && claim.agent_id.is_none()
            && claim.agent_verification_method.is_none()
            && claim.agent_key_authorize_event_id.is_none()
            && claim.pairwise_verification_method.is_none() => {}
        (
            arkret_models_collaboration::events_payloads::MlsWelcomeRecipient::NativeAgent {
                recipient_agent_id,
                recipient_agent_verification_method,
                agent_key_authorize_event_id,
            },
            arkret_models_collaboration::events_payloads::MlsClaimTrustBinding::AgentKeyAuthorizeEventId(claim_ref_event_id),
        ) if claim.device_id.is_none()
            && claim.device_authorize_event_id.is_none()
            && claim.agent_id.as_ref() == Some(recipient_agent_id)
            && claim.agent_verification_method.as_ref() == Some(recipient_agent_verification_method)
            && claim.agent_key_authorize_event_id.as_ref() == Some(agent_key_authorize_event_id)
            && claim_ref_event_id.as_str() == agent_key_authorize_event_id.as_str()
            && claim.pairwise_verification_method.is_none() => {}
        (
            arkret_models_collaboration::events_payloads::MlsWelcomeRecipient::MinimalMetadataPairwise {
                recipient_pairwise_actor_id,
                recipient_pairwise_verification_method,
            },
            arkret_models_collaboration::events_payloads::MlsClaimTrustBinding::MinimalMetadataPairwise {
                pairwise_actor_id,
                pairwise_verification_method,
            },
        ) if recipient_pairwise_actor_id == &claim.principal_id
            && pairwise_actor_id == recipient_pairwise_actor_id
            && pairwise_verification_method == recipient_pairwise_verification_method
            && claim.device_id.is_none()
            && claim.device_authorize_event_id.is_none()
            && claim.agent_id.is_none()
            && claim.agent_verification_method.is_none()
            && claim.agent_key_authorize_event_id.is_none()
            && claim.pairwise_verification_method.as_ref()
                == Some(recipient_pairwise_verification_method) => {}
        _ => return Err("peer_claim_welcome_invalid"),
    }
    Ok(())
}

fn peer_claim_state_allows_welcome(state: &str) -> bool {
    matches!(state, "claimed" | "last_resort_claimed")
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
        arkret_wire::DidCoreId::new(source_service_id.to_owned())
            .map_err(|error| AppError::internal(format!("peer service DID invalid: {error}")))?,
        now(),
    )?;
    let record = PeerKeyPackageClaimLedgerRecord {
        source_service_id: source_service_id.to_owned(),
        claim_request_id: body.claim_request_id.as_str().to_owned(),
        request_digest: request_digest.to_owned(),
        key_package_use: "none".to_owned(),
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
    source_service_id: arkret_wire::DidCoreId,
    terminal_at: DateTime<Utc>,
) -> Result<KeyPackageClaimTerminalReceipt, AppError> {
    let verification_method = format!(
        "{}#notary-key",
        state.service_resolution_commitment().full_id
    );
    let mut receipt = KeyPackageClaimTerminalReceipt {
        domain: arkret_wire::NonEmptyString::new(
            arkret_wire::DomainSeparationId::KEYPACKAGE_CLAIM_TERMINAL_RECEIPT_V1,
        )
        .expect("terminal receipt domain is non-empty"),
        claim_request_id,
        request_digest,
        terminal_state,
        key_package_refs,
        source_service_id,
        destination_service_id: arkret_wire::DidCoreId::new(state.service_id().clone())
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
    if !matches!(
        record.state.as_str(),
        "claimed" | "last_resort_claimed" | "consumed"
    ) {
        return Err(peer_claim_failed());
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
        .with_status(StatusCode::BAD_REQUEST)
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
    if !matches!(
        &body.requester_authorization,
        PeerKeyPackageRequesterAuthorization::MinimalMetadataPairwise { .. }
    ) && body.requester.as_str() != session.actor
    {
        return Err(AppError::capability_denied(
            "requester must match the calling session",
        ));
    }
    body.validate_shape()
        .map_err(|error| peer_claim_schema_violation(error.to_string()))?;
    let peer_body = PeerKeyPackagesClaimRequestBody::from(&body);
    validate_peer_claim_time_window(&peer_body)?;
    let local_service_id = state.service_id();
    if body.service_binding.source_service_id.as_str() != local_service_id {
        return Err(peer_claim_schema_violation(
            "self claim transport source must be the authenticated local service",
        ));
    }
    match &body.requester_authorization {
        PeerKeyPackageRequesterAuthorization::Device {
            requester_device_id,
            ..
        } if requester_device_id.as_str() == session.device_id => {}
        PeerKeyPackageRequesterAuthorization::NativeAgent {
            requester_agent_id, ..
        } if requester_agent_id.as_str() == session.actor => {}
        PeerKeyPackageRequesterAuthorization::MinimalMetadataPairwise { .. } => {}
        _ => {
            return Err(AppError::capability_denied(
                "requester authorization must match the authenticated session",
            ));
        }
    }
    if !verify_peer_claim_participant_authorization(state, &peer_body).await? {
        return Err(AppError::capability_denied(
            "requester authorization is not current at the source service",
        ));
    }
    if body.claim_purpose == PeerKeyPackageClaimPurpose::RealmMembership {
        let requester_is_current_member = state
            .projections()
            .snapshot()
            .member(body.intended_realm_id.as_str(), body.requester.as_str())
            .is_some_and(|member| {
                member.state == "join"
                    && member.recipient_service_id.as_deref() == Some(local_service_id)
            });
        if !requester_is_current_member {
            return Err(AppError::capability_denied(
                "requester has no current source-side Realm membership",
            ));
        }
    }
    if body.service_binding.destination_service_id.as_str() != local_service_id {
        let destination = body.service_binding.destination_service_id.as_str();
        let snapshot = state.projections().snapshot();
        let target_binding = snapshot
            .member(
                body.intended_realm_id.as_str(),
                body.target_principal_id.as_str(),
            )
            .filter(|member| member.state == "join")
            .and_then(|member| member.recipient_service_id.as_deref());
        if target_binding != Some(destination) {
            return Err(AppError::capability_denied(
                "destination service must equal the target's current Realm delivery binding",
            ));
        }
        let body_value = serde_json::to_value(&body)
            .map_err(|error| AppError::internal(format!("remote claim serialize: {error}")))?;
        let request_digest = arkret_canonical::canonical_sha256(&body_value)
            .map_err(|error| AppError::internal(format!("remote claim digest: {error}")))?;
        if let Some(existing) = state
            .mls_key_packages()
            .peer_claim(local_service_id, body.claim_request_id.as_str())
            .await
            .map_err(|error| AppError::internal(format!("remote claim relay ledger: {error}")))?
        {
            return replay_peer_claim(existing, &request_digest)
                .map(|Json(outcome)| Json(outcome.into()));
        }
        let target = crate::routing::federation::federation::resolved_peer_target(
            state,
            destination,
            "principal_server",
            false,
        )
        .await
        .map_err(|error| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                format!("remote KeyPackage authority route unavailable: {error}"),
            )
            .with_wire_code("dependency_unavailable")
        })?;
        let payload = String::from_utf8(arkret_canonical::canonical_json_bytes(&body).map_err(
            |error| AppError::internal(format!("remote claim canonical body: {error}")),
        )?)
        .map_err(|error| AppError::internal(format!("remote claim body utf8: {error}")))?;
        crate::routing::federation::outbox::enqueue_outbound(
            state,
            &target.base_url,
            destination,
            "/_arkret/peer/keys/keypackages/claim",
            body.claim_request_id.as_str(),
            &payload,
        )
        .await
        .map_err(|error| AppError::internal(format!("remote claim durable relay: {error}")))?;
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "remote KeyPackage claim has been durably accepted for relay",
        )
        .with_status(StatusCode::SERVICE_UNAVAILABLE)
        .with_wire_code("dependency_unavailable"));
    }
    claim_keypackage_at_destination(state, &peer_body)
        .await
        .map(|Json(outcome)| Json(outcome.into()))
}

pub(crate) async fn capture_relayed_keypackage_claim_outcome(
    state: &AppState,
    destination_service_id: &str,
    request_body: &str,
    response_body: &str,
) -> Result<(), String> {
    let request: KeyPackagesClaimRequestBody =
        serde_json::from_str(request_body).map_err(|error| error.to_string())?;
    let outcome: KeyPackagesClaimOutcome =
        serde_json::from_str(response_body).map_err(|error| error.to_string())?;
    outcome
        .validate_shape()
        .map_err(|error| error.to_string())?;
    let receipt = &outcome.claim_receipt;
    if request.service_binding.source_service_id.as_str() != state.service_id()
        || request.service_binding.destination_service_id.as_str() != destination_service_id
        || receipt.source_service_id != request.service_binding.source_service_id
        || receipt.destination_service_id != request.service_binding.destination_service_id
        || receipt.request != request.unsigned_request()
    {
        return Err("relayed KeyPackage claim outcome binding mismatch".to_owned());
    }
    let request_digest =
        arkret_canonical::canonical_sha256(&request).map_err(|error| error.to_string())?;
    if receipt.request_digest.as_str() != request_digest {
        return Err("relayed KeyPackage claim request digest mismatch".to_owned());
    }
    if !receipt
        .signature
        .signature_algorithm
        .as_ref()
        .is_some_and(|algorithm| algorithm.as_str() == "Ed25519")
    {
        return Err("relayed KeyPackage claim receipt algorithm invalid".to_owned());
    }
    let signing_bytes =
        peer_keypackage_claim_receipt_signing_bytes(receipt).map_err(|error| error.to_string())?;
    crate::jws_verify::validate_verification_method_controller(
        destination_service_id,
        receipt.signature.kid.as_str(),
    )?;
    let verification_key =
        crate::jws_verify::resolve_ed25519_pubkey_async(state, receipt.signature.kid.as_str())
            .await?;
    if !crate::routing::identity::device_signing::ed25519_verify(
        &verification_key,
        &signing_bytes,
        receipt.signature.sig.as_str(),
    ) {
        return Err("relayed KeyPackage claim receipt signature invalid".to_owned());
    }
    let is_last_resort = outcome
        .claims
        .iter()
        .any(|claim| claim.last_resort == Some(true));
    let record = PeerKeyPackageClaimLedgerRecord {
        source_service_id: state.service_id().clone(),
        claim_request_id: request.claim_request_id.as_str().to_owned(),
        request_digest,
        key_package_use: if is_last_resort {
            "last_resort"
        } else {
            "single_use"
        }
        .to_owned(),
        state: if is_last_resort {
            "last_resort_claimed"
        } else {
            "claimed"
        }
        .to_owned(),
        outcome: Some(serde_json::to_value(outcome).map_err(|error| error.to_string())?),
        consume_receipt: None,
        terminal_receipt: None,
        keypackage_id: None,
        claim_expires_at_unix_ms: Some(request.expires_at.timestamp_millis()),
        expires_at: (request.expires_at + chrono::Duration::minutes(10)).timestamp(),
        updated_at: now().timestamp(),
    };
    match state
        .mls_key_packages()
        .store_peer_claim_terminal(&record)
        .await
        .map_err(|error| error.to_string())?
    {
        PeerKeyPackageClaimLedgerWriteResult::Inserted => Ok(()),
        PeerKeyPackageClaimLedgerWriteResult::Existing(existing)
            if existing.request_digest == record.request_digest
                && existing.key_package_use == record.key_package_use
                && existing.outcome == record.outcome =>
        {
            Ok(())
        }
        PeerKeyPackageClaimLedgerWriteResult::Existing(_) => {
            Err("relayed KeyPackage claim request id conflict".to_owned())
        }
    }
}

pub(crate) async fn capture_relayed_keypackage_claim_query(
    state: &AppState,
    destination_service_id: &str,
    request_body: &str,
    query: &PeerKeyPackagesClaimQueryOutcome,
) -> Result<(), String> {
    query.validate_shape().map_err(|error| error.to_string())?;
    if matches!(
        query.state,
        PeerKeyPackagesClaimQueryState::Claimed | PeerKeyPackagesClaimQueryState::Consumed
    ) {
        let outcome = query
            .claim_outcome
            .as_ref()
            .ok_or_else(|| "claim query omitted its outcome".to_owned())?;
        capture_relayed_keypackage_claim_outcome(
            state,
            destination_service_id,
            request_body,
            &serde_json::to_string(outcome).map_err(|error| error.to_string())?,
        )
        .await?;
        if query.state == PeerKeyPackagesClaimQueryState::Claimed {
            return Ok(());
        }
        let request: KeyPackagesClaimRequestBody =
            serde_json::from_str(request_body).map_err(|error| error.to_string())?;
        let request_digest =
            arkret_canonical::canonical_sha256(&request).map_err(|error| error.to_string())?;
        let consume = query
            .consume_receipt
            .as_ref()
            .ok_or_else(|| "consumed claim query omitted its consume receipt".to_owned())?;
        consume.validate_shape().map_err(str::to_owned)?;
        let claim = outcome
            .claims
            .first()
            .filter(|_| outcome.claims.len() == 1)
            .ok_or_else(|| "consumed claim query has no unique claim".to_owned())?;
        if consume.recipient_durable_receipt.claim_request_id != request.claim_request_id
            || consume
                .recipient_durable_receipt
                .recipient_service_id
                .as_str()
                != destination_service_id
            || consume.claim_id.as_str() != claim.claim_id
            || consume.recipient_durable_receipt.key_package_ref.as_str() != claim.keypackage_ref
        {
            return Err("consumed claim query receipt binding mismatch".to_owned());
        }
        crate::jws_verify::validate_verification_method_controller(
            consume
                .recipient_durable_receipt
                .recipient_service_id
                .as_str(),
            consume.signature.kid.as_str(),
        )?;
        let signing_bytes = consume
            .canonical_signing_bytes()
            .map_err(|error| error.to_string())?;
        let key =
            crate::jws_verify::resolve_ed25519_pubkey_async(state, consume.signature.kid.as_str())
                .await?;
        if !crate::routing::identity::device_signing::ed25519_verify(
            &key,
            &signing_bytes,
            consume.signature.sig.as_str(),
        ) {
            return Err("consumed claim query receipt signature invalid".to_owned());
        }
        let consume_value = serde_json::to_value(consume).map_err(|error| error.to_string())?;
        let outcome_value = serde_json::to_value(outcome).map_err(|error| error.to_string())?;
        let attached = state
            .mls_key_packages()
            .transition_peer_claim_consumed(
                state.service_id(),
                request.claim_request_id.as_str(),
                &request_digest,
                &outcome_value,
                &consume_value,
                consume.consumed_at.timestamp_millis(),
            )
            .await
            .map_err(|error| error.to_string())?;
        if attached.is_none() {
            let winner = state
                .mls_key_packages()
                .peer_claim(state.service_id(), request.claim_request_id.as_str())
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| {
                    "consumed claim query could not reload its durable source ledger".to_owned()
                })?;
            if !consumed_query_source_winner_matches(
                &winner.state,
                &winner.request_digest,
                winner.consume_receipt.as_ref(),
                &request_digest,
                &consume_value,
            ) {
                return Err(
                    "consumed claim query conflicts with the durable source winner".to_owned(),
                );
            }
        }
        return Ok(());
    }
    let request: KeyPackagesClaimRequestBody =
        serde_json::from_str(request_body).map_err(|error| error.to_string())?;
    let request_digest =
        arkret_canonical::canonical_sha256(&request).map_err(|error| error.to_string())?;
    let terminal = query
        .terminal_receipt
        .as_ref()
        .ok_or_else(|| "terminal claim query omitted its signed receipt".to_owned())?;
    if terminal.validate_shape().is_err()
        || terminal.claim_request_id != request.claim_request_id
        || terminal.request_digest.as_str() != request_digest
        || terminal.source_service_id != request.service_binding.source_service_id
        || terminal.destination_service_id != request.service_binding.destination_service_id
        || terminal.destination_service_id.as_str() != destination_service_id
        || terminal.terminal_state
            != match query.state {
                PeerKeyPackagesClaimQueryState::ClaimFailed => {
                    KeyPackageClaimTerminalState::NeverClaimed
                }
                PeerKeyPackagesClaimQueryState::Expired => KeyPackageClaimTerminalState::Expired,
                PeerKeyPackagesClaimQueryState::Revoked => KeyPackageClaimTerminalState::Revoked,
                _ => return Err("non-terminal claim query cannot close relay".to_owned()),
            }
    {
        return Err("terminal claim query binding mismatch".to_owned());
    }
    let signing_bytes = terminal
        .canonical_signing_bytes()
        .map_err(|error| error.to_string())?;
    crate::jws_verify::validate_verification_method_controller(
        destination_service_id,
        terminal.signature.kid.as_str(),
    )?;
    let verification_key =
        crate::jws_verify::resolve_ed25519_pubkey_async(state, terminal.signature.kid.as_str())
            .await?;
    if !crate::routing::identity::device_signing::ed25519_verify(
        &verification_key,
        &signing_bytes,
        terminal.signature.sig.as_str(),
    ) {
        return Err("terminal claim query receipt signature invalid".to_owned());
    }
    let state_name = match query.state {
        PeerKeyPackagesClaimQueryState::ClaimFailed => "claim_failed",
        PeerKeyPackagesClaimQueryState::Expired => "expired",
        PeerKeyPackagesClaimQueryState::Revoked => "revoked",
        _ => return Err("non-terminal claim query cannot close relay".to_owned()),
    };
    if matches!(state_name, "expired" | "revoked") {
        let outcome = query.claim_outcome.as_ref().ok_or_else(|| {
            "terminal successful claim query omitted its claim outcome".to_owned()
        })?;
        let outcome_refs = outcome
            .claims
            .iter()
            .map(|claim| claim.keypackage_ref.as_str())
            .collect::<Vec<_>>();
        let terminal_refs = terminal.key_package_refs.as_deref().ok_or_else(|| {
            "terminal successful claim receipt omitted KeyPackage refs".to_owned()
        })?;
        if !terminal_claim_coordinates_match(
            state_name,
            request.expires_at.timestamp_millis(),
            terminal.terminal_at.timestamp_millis(),
            terminal_refs.iter().map(String::as_str),
            outcome_refs,
        ) {
            return Err("terminal claim query receipt coordinates mismatch".to_owned());
        }
    }
    let terminal_receipt_value =
        serde_json::to_value(terminal).map_err(|error| error.to_string())?;
    let record = PeerKeyPackageClaimLedgerRecord {
        source_service_id: state.service_id().clone(),
        claim_request_id: request.claim_request_id.as_str().to_owned(),
        request_digest,
        key_package_use: "none".to_owned(),
        state: state_name.to_owned(),
        outcome: query
            .claim_outcome
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| error.to_string())?,
        consume_receipt: query
            .consume_receipt
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| error.to_string())?,
        terminal_receipt: Some(terminal_receipt_value.clone()),
        keypackage_id: None,
        claim_expires_at_unix_ms: Some(request.expires_at.timestamp_millis()),
        expires_at: (request.expires_at + chrono::Duration::minutes(10)).timestamp(),
        updated_at: now().timestamp(),
    };
    if matches!(state_name, "expired" | "revoked") {
        let expected_outcome = record.outcome.as_ref().ok_or_else(|| {
            "terminal successful claim query omitted its claim outcome".to_owned()
        })?;
        if state
            .mls_key_packages()
            .transition_peer_claim_terminal(
                state.service_id(),
                request.claim_request_id.as_str(),
                &record.request_digest,
                expected_outcome,
                state_name,
                &terminal_receipt_value,
                now().timestamp_millis(),
            )
            .await
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Ok(());
        }
        if let Some(existing) = state
            .mls_key_packages()
            .peer_claim(state.service_id(), request.claim_request_id.as_str())
            .await
            .map_err(|error| error.to_string())?
        {
            if existing.request_digest == record.request_digest
                && existing.state == state_name
                && existing.outcome == record.outcome
                && existing.terminal_receipt.as_ref() == Some(&terminal_receipt_value)
            {
                return Ok(());
            }
            return Err("terminal claim query conflicts with durable source ledger".to_owned());
        }
    }
    match state
        .mls_key_packages()
        .store_peer_claim_terminal(&record)
        .await
        .map_err(|error| error.to_string())?
    {
        PeerKeyPackageClaimLedgerWriteResult::Inserted => Ok(()),
        PeerKeyPackageClaimLedgerWriteResult::Existing(existing)
            if claim_failed_source_winner_matches(&existing, &record) =>
        {
            Ok(())
        }
        PeerKeyPackageClaimLedgerWriteResult::Existing(_) => {
            Err("terminal claim query request id conflict".to_owned())
        }
    }
}

fn consumed_query_source_winner_matches(
    state: &str,
    stored_request_digest: &str,
    stored_consume_receipt: Option<&Value>,
    expected_request_digest: &str,
    expected_consume_receipt: &Value,
) -> bool {
    state == "consumed"
        && stored_request_digest == expected_request_digest
        && stored_consume_receipt == Some(expected_consume_receipt)
}

fn terminal_claim_coordinates_match<'a>(
    state: &str,
    request_expires_at_unix_ms: i64,
    terminal_at_unix_ms: i64,
    terminal_refs: impl IntoIterator<Item = &'a str>,
    outcome_refs: impl IntoIterator<Item = &'a str>,
) -> bool {
    terminal_refs.into_iter().eq(outcome_refs)
        && (state != "expired" || terminal_at_unix_ms >= request_expires_at_unix_ms)
}

fn claim_failed_source_winner_matches(
    stored: &PeerKeyPackageClaimLedgerRecord,
    expected: &PeerKeyPackageClaimLedgerRecord,
) -> bool {
    stored.request_digest == expected.request_digest
        && stored.key_package_use == "none"
        && stored.state == "claim_failed"
        && stored.outcome.is_none()
        && stored.consume_receipt.is_none()
        && stored.keypackage_id.is_none()
        && stored.claim_expires_at_unix_ms == expected.claim_expires_at_unix_ms
        && stored.expires_at == expected.expires_at
        && stored.terminal_receipt == expected.terminal_receipt
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
    let durable_receipt = &body.recipient_durable_receipt;
    if !matches!(
        &durable_receipt.recipient,
        arkret_models_crypto::RecipientMlsDurableSigner::MinimalMetadataPairwise { .. }
    ) && durable_receipt.recipient_principal_id.as_str() != session.actor
    {
        return Err(AppError::capability_denied(
            "durable recipient principal must match the calling principal",
        ));
    }
    let consume_signing_input =
        arkret_models_crypto::http_bodies::keypackages_consume_signing_input(&body.unsigned())
            .map_err(|error| {
                AppError::param_invalid(format!(
                    "KeyPackage consume canonical input failed: {error}"
                ))
            })?;
    let keypackage_refs = [durable_receipt.key_package_ref.to_string()];
    verify_keypackage_consumer_signature(
        state,
        &session,
        &durable_receipt.recipient_principal_id,
        &durable_receipt.recipient,
        Some(&durable_receipt.realm_id),
        &keypackage_refs,
        &body.signature,
        &consume_signing_input,
    )
    .await?;
    validate_recipient_durable_receipt(state, &session, &body).await?;
    validate_direct_keypackage_consume(state, &body).await?;
    validate_sidecar_keypackage_consume(state, &body).await?;
    let group_id = consume_group_ref(&body);
    let record = state
        .mls_key_packages()
        .key_package_by_ref(durable_receipt.key_package_ref.as_str())
        .await
        .map_err(|error| AppError::internal(format!("KeyPackage lookup failed: {error}")))?
        .ok_or_else(|| AppError::conflict("KeyPackage is missing or no longer claimable"))?;
    if !keypackage_record_matches_consumer(&record, &body, &session) {
        return Err(AppError::capability_denied(
            "KeyPackage consume endpoint is not the published owner",
        ));
    }
    let lifecycle = record.lifecycle().map_err(AppError::internal)?;
    if matches!(
        lifecycle.reuse_policy,
        PersistedKeyPackageReusePolicy::LastResort { .. }
    ) {
        return consume_last_resort_keypackage(state, &body, &record).await;
    }
    if let PersistedKeyPackageClaimState::Consumed { mls_group_id, .. } = &lifecycle.claim_state {
        if mls_group_id.as_str() != group_id.as_str() {
            return Err(AppError::conflict(
                "KeyPackage was consumed by another MLS group",
            ));
        }
        let ledger = state
            .mls_key_packages()
            .peer_claim_by_keypackage_id(&record.id)
            .await
            .map_err(|error| {
                AppError::internal(format!("peer claim replay lookup failed: {error}"))
            })?
            .ok_or_else(|| {
                AppError::internal("consumed KeyPackage is missing its durable claim ledger")
            })?;
        if ledger.state != "consumed" {
            return Err(AppError::internal(
                "consumed KeyPackage ledger is not terminal",
            ));
        }
        let stored_receipt = ledger
            .consume_receipt
            .map(serde_json::from_value::<KeyPackageConsumeReceipt>)
            .transpose()
            .map_err(|error| {
                AppError::internal(format!("stored consume receipt invalid: {error}"))
            })?
            .ok_or_else(|| {
                AppError::internal("consumed KeyPackage ledger has no durable receipt")
            })?;
        validate_consume_receipt_replay(state, &body, &stored_receipt)?;
        return json_ok(KeyPackagesConsumeOutcome {
            consume_receipt: stored_receipt,
        });
    }
    if !matches!(
        lifecycle.claim_state,
        PersistedKeyPackageClaimState::Claimed { .. }
    ) {
        return Err(AppError::conflict(
            "KeyPackage has no active claim to consume",
        ));
    }
    let consumed_at_datetime = now();
    let consumed_at_unix_ms = consumed_at_datetime.timestamp_millis();
    let prepared_consume_receipt =
        build_keypackage_consume_receipt(state, &body, consumed_at_datetime)?;
    let prepared_consume_receipt_value = serde_json::to_value(&prepared_consume_receipt)
        .map_err(|error| AppError::internal(format!("consume receipt serialize: {error}")))?;
    let Some(consumed) = state
        .mls_key_packages()
        .consume_key_package_claim(
            &record.id,
            &group_id,
            consumed_at_unix_ms,
            Some(&prepared_consume_receipt_value),
        )
        .await
        .map_err(|error| AppError::internal(format!("KeyPackage consume CAS failed: {error}")))?
    else {
        let winner = state
            .mls_key_packages()
            .peer_claim_by_keypackage_id(&record.id)
            .await
            .map_err(|error| {
                AppError::internal(format!("concurrent consume winner lookup failed: {error}"))
            })?
            .filter(|ledger| ledger.state == "consumed")
            .and_then(|ledger| ledger.consume_receipt)
            .map(serde_json::from_value::<KeyPackageConsumeReceipt>)
            .transpose()
            .map_err(|error| {
                AppError::internal(format!("concurrent consume receipt invalid: {error}"))
            })?
            .ok_or_else(|| AppError::conflict("KeyPackage claim changed before consume"))?;
        validate_consume_receipt_replay(state, &body, &winner)?;
        return json_ok(KeyPackagesConsumeOutcome {
            consume_receipt: winner,
        });
    };
    state
        .projections()
        .mark_key_package_consumed(&consumed.id, consumed_at_unix_ms.div_euclid(1000));
    json_ok(KeyPackagesConsumeOutcome {
        consume_receipt: prepared_consume_receipt,
    })
}

async fn consume_last_resort_keypackage(
    state: &AppState,
    body: &KeyPackagesConsumeRequestBody,
    record: &MlsKeyPackageRow,
) -> JsonResult<KeyPackagesConsumeOutcome> {
    let durable = &body.recipient_durable_receipt;
    let stored = state
        .event_queries()
        .accepted_event(durable.welcome_ref.as_str())
        .await
        .map_err(|error| AppError::internal(format!("Welcome lookup failed: {error}")))?
        .ok_or_else(|| AppError::new(ErrorCode::FailedPrecondition, "Welcome is not accepted"))?;
    let event = serde_json::from_value::<arkret_wire::Event>(stored.envelope)
        .map_err(|error| AppError::internal(format!("stored Welcome invalid: {error}")))?;
    let welcome = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::MlsWelcomePayload,
    >(serde_json::to_value(event.payload).map_err(|error| {
        AppError::internal(format!("stored Welcome payload serialize: {error}"))
    })?)
    .map_err(|error| AppError::internal(format!("stored Welcome payload invalid: {error}")))?;
    let source_service_id = welcome.claim_receipt.source_service_id.as_str();
    let claim_request_id = durable.claim_request_id.as_str();
    let ledger = state
        .mls_key_packages()
        .peer_claim(source_service_id, claim_request_id)
        .await
        .map_err(|error| AppError::internal(format!("last-resort claim lookup failed: {error}")))?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "last-resort consume has no exact durable claim audit",
            )
        })?;
    if ledger.keypackage_id.as_deref() != Some(record.id.as_str()) {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "last-resort claim audit names another KeyPackage",
        ));
    }
    let claim_outcome = ledger
        .outcome
        .as_ref()
        .map(|value| serde_json::from_value::<PeerKeyPackagesClaimOutcome>(value.clone()))
        .transpose()
        .map_err(|error| {
            AppError::internal(format!("stored last-resort claim outcome invalid: {error}"))
        })?
        .ok_or_else(|| {
            AppError::internal("last-resort claim audit has no durable claim outcome")
        })?;
    claim_outcome
        .validate_shape()
        .map_err(|error| AppError::internal(format!("stored claim outcome shape: {error}")))?;
    if !last_resort_claim_coordinates_match(
        claim_outcome.claim_request_id.as_str(),
        durable.claim_request_id.as_str(),
        claim_outcome
            .claims
            .iter()
            .map(|claim| (claim.claim_id.as_str(), claim.keypackage_ref.as_str())),
        body.claim_id.as_str(),
        durable.key_package_ref.as_str(),
    ) {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "last-resort claim audit differs from the accepted Welcome claim",
        ));
    }
    if ledger.state == "consumed" {
        let stored_receipt = ledger
            .consume_receipt
            .map(serde_json::from_value::<KeyPackageConsumeReceipt>)
            .transpose()
            .map_err(|error| {
                AppError::internal(format!(
                    "stored last-resort consume receipt invalid: {error}"
                ))
            })?
            .ok_or_else(|| {
                AppError::internal("consumed last-resort claim audit has no durable receipt")
            })?;
        validate_consume_receipt_replay(state, body, &stored_receipt)?;
        return json_ok(KeyPackagesConsumeOutcome {
            consume_receipt: stored_receipt,
        });
    }
    if ledger.state != "last_resort_claimed" {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "last-resort claim audit is not consumable",
        ));
    }
    let consumed_at = now();
    let receipt = build_keypackage_consume_receipt(state, body, consumed_at)?;
    let receipt_value = serde_json::to_value(&receipt)
        .map_err(|error| AppError::internal(format!("consume receipt serialize: {error}")))?;
    let ledger_request_digest = ledger.request_digest.clone();
    let attached = state
        .mls_key_packages()
        .attach_peer_claim_consume_receipt(
            source_service_id,
            claim_request_id,
            &ledger_request_digest,
            &receipt_value,
            consumed_at.timestamp_millis(),
        )
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "last-resort consume receipt persist failed: {error}"
            ))
        })?;
    let Some(attached) = attached else {
        let winner = state
            .mls_key_packages()
            .peer_claim(source_service_id, claim_request_id)
            .await
            .map_err(|error| {
                AppError::internal(format!(
                    "concurrent last-resort consume winner lookup failed: {error}"
                ))
            })?
            .filter(|ledger| {
                ledger.state == "consumed"
                    && ledger.request_digest == ledger_request_digest
                    && ledger.keypackage_id.as_deref() == Some(record.id.as_str())
            })
            .and_then(|ledger| ledger.consume_receipt)
            .map(serde_json::from_value::<KeyPackageConsumeReceipt>)
            .transpose()
            .map_err(|error| {
                AppError::internal(format!(
                    "concurrent last-resort consume receipt invalid: {error}"
                ))
            })?
            .ok_or_else(|| AppError::conflict("last-resort claim audit changed before consume"))?;
        validate_consume_receipt_replay(state, body, &winner)?;
        return json_ok(KeyPackagesConsumeOutcome {
            consume_receipt: winner,
        });
    };
    if attached.consume_receipt.as_ref() != Some(&receipt_value) {
        return Err(AppError::internal(
            "last-resort claim audit did not retain the exact consume receipt",
        ));
    }
    // The claim audit becomes terminal, but the reusable KeyPackage row stays
    // published: no ordinary consume CAS or projection transition is invoked.
    json_ok(KeyPackagesConsumeOutcome {
        consume_receipt: receipt,
    })
}

fn last_resort_claim_coordinates_match<'a>(
    outcome_request_id: &str,
    durable_request_id: &str,
    claims: impl IntoIterator<Item = (&'a str, &'a str)>,
    expected_claim_id: &str,
    expected_keypackage_ref: &str,
) -> bool {
    outcome_request_id == durable_request_id
        && claims.into_iter().any(|(claim_id, keypackage_ref)| {
            claim_id == expected_claim_id && keypackage_ref == expected_keypackage_ref
        })
}

async fn validate_recipient_durable_receipt(
    state: &AppState,
    session: &SessionRecord,
    body: &KeyPackagesConsumeRequestBody,
) -> Result<(), AppError> {
    let receipt = &body.recipient_durable_receipt;
    if receipt.domain.as_str() != arkret_wire::DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1
        || receipt.recipient_service_id.as_str() != state.service_id()
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "recipient durable receipt differs from the consume coordinates",
        ));
    }
    let stored = state
        .event_queries()
        .accepted_event(receipt.welcome_ref.as_str())
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
    let welcome_digest = welcome_digest_from_inline_carrier(&welcome);
    let welcome_recipient_matches = match (&welcome.recipient, &receipt.recipient) {
        (
            arkret_models_collaboration::events_payloads::MlsWelcomeRecipient::Device {
                recipient_device_id,
            },
            arkret_models_crypto::RecipientMlsDurableSigner::Device {
                recipient_device_id: durable_recipient_device_id,
                ..
            },
        ) => {
            welcome.recipient_principal_id.as_ref() == Some(&receipt.recipient_principal_id)
                && recipient_device_id == durable_recipient_device_id
        }
        (
            arkret_models_collaboration::events_payloads::MlsWelcomeRecipient::NativeAgent {
                recipient_agent_id,
                recipient_agent_verification_method,
                agent_key_authorize_event_id,
            },
            arkret_models_crypto::RecipientMlsDurableSigner::NativeAgent {
                recipient_agent_id: durable_recipient_agent_id,
                recipient_agent_verification_method: durable_recipient_agent_verification_method,
                agent_key_authorize_event_id: durable_agent_key_authorize_event_id,
            },
        ) => {
            welcome.recipient_principal_id.as_ref() == Some(&receipt.recipient_principal_id)
                && recipient_agent_id == durable_recipient_agent_id
                && recipient_agent_verification_method
                    == durable_recipient_agent_verification_method
                && agent_key_authorize_event_id == durable_agent_key_authorize_event_id
        }
        (
            arkret_models_collaboration::events_payloads::MlsWelcomeRecipient::MinimalMetadataPairwise {
                recipient_pairwise_actor_id,
                recipient_pairwise_verification_method,
            },
            arkret_models_crypto::RecipientMlsDurableSigner::MinimalMetadataPairwise {
                recipient_pairwise_verification_method:
                    durable_recipient_pairwise_verification_method,
            },
        ) => {
            welcome.recipient_principal_id.is_none()
                && recipient_pairwise_actor_id == &receipt.recipient_principal_id
                && recipient_pairwise_verification_method
                    == durable_recipient_pairwise_verification_method
        }
        _ => false,
    };
    if !welcome_recipient_matches
        || welcome.claim_receipt.claim_request_id != receipt.claim_request_id
        || welcome.keypackage_ref != receipt.key_package_ref.as_str()
        || welcome.claim_id.as_str() != body.claim_id.as_str()
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
    verify_keypackage_consumer_signature(
        state,
        session,
        &receipt.recipient_principal_id,
        &receipt.recipient,
        Some(&receipt.realm_id),
        std::slice::from_ref(&receipt.key_package_ref.to_string()),
        &receipt.signature,
        &signing_input,
    )
    .await
}

async fn verify_keypackage_consumer_signature(
    state: &AppState,
    session: &SessionRecord,
    owner: &arkret_wire::DidCoreId,
    consumer: &arkret_models_crypto::RecipientMlsDurableSigner,
    realm_id: Option<&RealmId>,
    keypackage_refs: &[String],
    signature: &KeyOperationSignature,
    signing_input: &[u8],
) -> Result<(), AppError> {
    match consumer {
        arkret_models_crypto::RecipientMlsDurableSigner::Device {
            recipient_device_id,
            ..
        } => {
            if recipient_device_id.as_str() != session.device_id {
                return Err(AppError::capability_denied(
                    "durable recipient device must match the calling session",
                ));
            }
            verify_session_keypackage_write_signature(
                state,
                session,
                keypackage_refs,
                signature,
                signing_input,
            )
            .await
        }
        arkret_models_crypto::RecipientMlsDurableSigner::NativeAgent {
            recipient_agent_id,
            recipient_agent_verification_method,
            agent_key_authorize_event_id,
        } => {
            if recipient_agent_id != owner
                || signature.kid.as_str() != recipient_agent_verification_method.as_str()
                || !current_agent_key_authorization_matches_method(
                    state,
                    recipient_agent_id,
                    agent_key_authorize_event_id.as_str(),
                    recipient_agent_verification_method.as_str(),
                )
                .await
            {
                return Err(AppError::capability_denied(
                    "Native Agent consume authority is not current",
                ));
            }
            let key = crate::jws_verify::resolve_ed25519_pubkey_async(
                state,
                recipient_agent_verification_method.as_str(),
            )
            .await
            .map_err(|_| AppError::capability_denied("Native Agent consume key is unavailable"))?;
            if !crate::routing::identity::device_signing::ed25519_verify(
                &key,
                signing_input,
                signature.sig.as_str(),
            ) {
                return Err(AppError::param_invalid("endpoint_signature_invalid"));
            }
            Ok(())
        }
        arkret_models_crypto::RecipientMlsDurableSigner::MinimalMetadataPairwise {
            recipient_pairwise_verification_method,
        } => {
            let endpoint = arkret_models_crypto::MlsEndpointIdentity::minimal_metadata_pairwise(
                owner.clone(),
                recipient_pairwise_verification_method.clone(),
            )
            .map_err(|_| AppError::capability_denied("pairwise consume endpoint mismatch"))?;
            let _ = endpoint;
            let realm_id = realm_id.ok_or_else(|| {
                AppError::new(
                    ErrorCode::FailedPrecondition,
                    "pairwise consume requires exact Realm affinity",
                )
            })?;
            ensure_pairwise_realm_affinity(
                state,
                owner,
                recipient_pairwise_verification_method,
                realm_id,
                state.service_id(),
            )
            .await?;
            if signature.kid.as_str() != recipient_pairwise_verification_method.as_str() {
                return Err(AppError::capability_denied(
                    "pairwise consume signature kid mismatch",
                ));
            }
            let multibase = recipient_pairwise_verification_method
                .as_str()
                .split_once('#')
                .and_then(|(controller, _)| controller.strip_prefix("did:key:"))
                .ok_or_else(|| AppError::capability_denied("pairwise consume method invalid"))?;
            let raw = arkret_canonical::decode_ed25519_multibase(multibase)
                .map_err(|_| AppError::capability_denied("pairwise consume method invalid"))?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&raw)
                .map_err(|_| AppError::capability_denied("pairwise consume method invalid"))?;
            if !crate::routing::identity::device_signing::ed25519_verify(
                &key,
                signing_input,
                signature.sig.as_str(),
            ) {
                return Err(AppError::param_invalid("endpoint_signature_invalid"));
            }
            Ok(())
        }
    }
}

fn keypackage_record_matches_consumer(
    record: &soland_services::events::MlsKeyPackageState,
    body: &KeyPackagesConsumeRequestBody,
    session: &SessionRecord,
) -> bool {
    let receipt = &body.recipient_durable_receipt;
    if record.actor_id != receipt.recipient_principal_id.as_str() {
        return false;
    }
    match &receipt.recipient {
        arkret_models_crypto::RecipientMlsDurableSigner::Device {
            recipient_device_id,
            ..
        } => {
            session.actor == record.actor_id
                && record.device_id.as_deref() == Some(recipient_device_id.as_str())
                && record.endpoint_verification_method.is_none()
                && record.intended_realm_id.is_none()
        }
        arkret_models_crypto::RecipientMlsDurableSigner::NativeAgent {
            recipient_agent_verification_method,
            agent_key_authorize_event_id,
            ..
        } => {
            session.actor == record.actor_id
                && record.device_id.is_none()
                && record.endpoint_verification_method.as_deref()
                    == Some(recipient_agent_verification_method.as_str())
                && record.intended_realm_id.is_none()
                && record.agent_key_authorize_event_id.as_deref()
                    == Some(agent_key_authorize_event_id.as_str())
        }
        arkret_models_crypto::RecipientMlsDurableSigner::MinimalMetadataPairwise {
            recipient_pairwise_verification_method,
        } => {
            record.device_id.is_none()
                && record.endpoint_verification_method.as_deref()
                    == Some(recipient_pairwise_verification_method.as_str())
                && record.intended_realm_id.as_deref()
                    == Some(body.recipient_durable_receipt.realm_id.as_str())
                && record.device_authorize_event_id.is_none()
                && record.agent_key_authorize_event_id.is_none()
        }
    }
}

fn build_keypackage_consume_receipt(
    state: &AppState,
    body: &KeyPackagesConsumeRequestBody,
    consumed_at: DateTime<Utc>,
) -> Result<KeyPackageConsumeReceipt, AppError> {
    let verification_method = format!(
        "{}#notary-key",
        state.service_resolution_commitment().full_id
    );
    let mut receipt = KeyPackageConsumeReceipt {
        domain: arkret_wire::NonEmptyString::new(
            arkret_wire::DomainSeparationId::KEYPACKAGE_CONSUME_RECEIPT_V1,
        )
        .expect("receipt domain is non-empty"),
        request_digest: consume_request_digest(body)?,
        claim_id: body.claim_id.clone(),
        recipient_durable_receipt: body.recipient_durable_receipt.clone(),
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

fn consume_request_digest(
    body: &KeyPackagesConsumeRequestBody,
) -> Result<arkret_wire::Hash, AppError> {
    let digest = arkret_canonical::canonical_sha256(&body.unsigned())
        .map_err(|error| AppError::internal(format!("consume request digest failed: {error}")))?;
    arkret_wire::Hash::new(digest)
        .map_err(|error| AppError::internal(format!("consume request digest invalid: {error}")))
}

fn validate_consume_receipt_replay(
    state: &AppState,
    body: &KeyPackagesConsumeRequestBody,
    receipt: &KeyPackageConsumeReceipt,
) -> Result<(), AppError> {
    receipt
        .validate_shape()
        .map_err(|error| AppError::internal(format!("stored consume receipt shape: {error}")))?;
    if receipt
        .recipient_durable_receipt
        .recipient_service_id
        .as_str()
        != state.service_id()
        || receipt.request_digest != consume_request_digest(body)?
        || receipt.claim_id != body.claim_id
        || serde_json::to_value(&receipt.recipient_durable_receipt).map_err(|error| {
            AppError::internal(format!("stored durable receipt serialize: {error}"))
        })? != serde_json::to_value(&body.recipient_durable_receipt).map_err(|error| {
            AppError::internal(format!("request durable receipt serialize: {error}"))
        })?
    {
        return Err(AppError::conflict(
            "consume replay differs from the durably accepted request",
        ));
    }
    let expected_method = format!(
        "{}#notary-key",
        state.service_resolution_commitment().full_id
    );
    if receipt.signature.kid.as_str() != expected_method
        || receipt
            .signature
            .signature_algorithm
            .as_ref()
            .is_some_and(|algorithm| algorithm.as_str() != "Ed25519")
    {
        return Err(AppError::internal(
            "stored consume receipt service signer is invalid",
        ));
    }
    let signing_input = receipt.canonical_signing_bytes().map_err(|error| {
        AppError::internal(format!(
            "stored consume receipt transcript invalid: {error}"
        ))
    })?;
    if !crate::routing::identity::device_signing::ed25519_verify(
        &state.notary_verifying_key(),
        &signing_input,
        receipt.signature.sig.as_str(),
    ) {
        return Err(AppError::internal(
            "stored consume receipt service signature is invalid",
        ));
    }
    Ok(())
}

fn welcome_digest_from_inline_carrier(
    welcome: &arkret_models_collaboration::events_payloads::MlsWelcomePayload,
) -> String {
    arkret_canonical::sha256_digest(welcome.carrier.welcome_bytes())
}

#[cfg(test)]
mod recipient_durable_receipt_tests {
    use super::welcome_digest_from_inline_carrier;

    #[test]
    fn receipt_digest_uses_decoded_welcome_bytes_not_event_envelope() {
        let fixture = arkret_schema::embedded_json_artifact(
            "fixtures/keypackage-pairwise-welcome-fixture.json",
        )
        .expect("embedded pairwise Welcome fixture");
        let instance = fixture["schema_validation_cases"][0]["instance"].clone();
        let welcome: arkret_models_collaboration::events_payloads::MlsWelcomePayload =
            serde_json::from_value(instance.clone()).expect("typed inline Welcome fixture");
        let digest = welcome_digest_from_inline_carrier(&welcome);

        assert_eq!(digest, welcome.claim_envelope.welcome_digest.as_str());
        let event_envelope = serde_json::json!({
            "kind": "ak.mls.welcome",
            "payload": instance,
        });
        assert_ne!(
            digest,
            arkret_canonical::canonical_sha256(&event_envelope)
                .expect("canonical Event-envelope digest")
        );
    }
}

async fn validate_direct_keypackage_consume(
    state: &AppState,
    body: &KeyPackagesConsumeRequestBody,
) -> Result<bool, AppError> {
    let realm_id = body.recipient_durable_receipt.realm_id.to_string();
    if !state
        .projections()
        .snapshot()
        .realm_is_direct_conversation(&realm_id)
    {
        return Ok(false);
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
    let welcome_ref = body.recipient_durable_receipt.welcome_ref.as_str();
    let realm_scope = arkret_wire::ScopeRef::Realm {
        realm_id: RealmId::new(realm_id.clone()).map_err(|error| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                format!("direct conversation Realm id is invalid: {error}"),
            )
        })?,
    };
    let group_id = realm_scope.canonical_mls_group_id().map_err(|error| {
        AppError::new(
            ErrorCode::FailedPrecondition,
            format!("direct conversation MLS group id derivation failed: {error}"),
        )
    })?;
    if body.recipient_durable_receipt.mls_group_id.as_str() != group_id.as_str() {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "KeyPackage consume does not reference the scope-derived direct conversation MLS group",
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
    let claim_id = &body.claim_id;
    let key_package_id = body.recipient_durable_receipt.key_package_ref.as_str();
    if !welcome_recipient_matches_consumer(&welcome, body)
        || welcome.mls_group_id.as_str() != group_id.as_str()
        || welcome.epoch != body.recipient_durable_receipt.mls_epoch
        || !welcome_claim_matches_consume(
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

fn welcome_claim_matches_consume(
    request_keypackage_ref: &str,
    consumed_claim_id: &str,
    welcome_keypackage_ref: &str,
    welcome_claim_id: &str,
) -> bool {
    request_keypackage_ref == welcome_keypackage_ref && consumed_claim_id == welcome_claim_id
}

#[cfg(test)]
mod direct_consume_tests {
    use super::welcome_claim_matches_consume;

    #[test]
    fn direct_consume_binds_the_wire_ref_without_assuming_claim_id_prefix() {
        let keypackage_ref = format!("sha256:{}", "a".repeat(64));
        let claim_id = "keypackage-01904100-0000-7000-8000-000000000001-claim-nonce";
        assert!(welcome_claim_matches_consume(
            &keypackage_ref,
            claim_id,
            &keypackage_ref,
            claim_id,
        ));
        assert!(!welcome_claim_matches_consume(
            &format!("sha256:{}", "b".repeat(64)),
            claim_id,
            &keypackage_ref,
            claim_id,
        ));
        assert!(!welcome_claim_matches_consume(
            &keypackage_ref,
            "different-claim",
            &keypackage_ref,
            claim_id,
        ));
    }
}

async fn validate_sidecar_keypackage_consume(
    state: &AppState,
    body: &KeyPackagesConsumeRequestBody,
) -> Result<(), AppError> {
    let group_id = body.recipient_durable_receipt.mls_group_id.as_str();
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
    let welcome_ref = body.recipient_durable_receipt.welcome_ref.as_str();
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
    let key_package_id = body.recipient_durable_receipt.key_package_ref.as_str();
    let claim_id = &body.claim_id;
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
        || welcome.epoch != body.recipient_durable_receipt.mls_epoch
        || body.recipient_durable_receipt.realm_id.as_str() != sidecar.realm_id.as_str()
        || !welcome_recipient_matches_consumer(&welcome, body)
        || !welcome_claim_matches_consume(
            key_package_id,
            claim_id,
            &welcome.keypackage_ref,
            welcome.claim_id.as_str(),
        )
        || sidecar_binding != &expected_sidecar_binding
        || welcome.governance_binding.realm_id().as_str() != sidecar.realm_id
        || welcome
            .governance_binding
            .sidecar_id()
            .map(ToString::to_string)
            .as_deref()
            != Some(sidecar.sidecar_id.as_str())
        || !current_epoch_matches
        || !state
            .projections()
            .snapshot()
            .accepted_mls_commit_refs
            .contains(welcome.commit_ref.as_str())
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
                && projected_welcome_matches_consumer(row, body)
                && row.key_package_id == key_package_id
                && row.epoch == welcome.epoch
                && row.commit_ref.as_deref() == Some(welcome.commit_ref.as_str())
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

fn welcome_recipient_matches_consumer(
    welcome: &arkret_models_collaboration::events_payloads::MlsWelcomePayload,
    body: &KeyPackagesConsumeRequestBody,
) -> bool {
    let receipt = &body.recipient_durable_receipt;
    match (&welcome.recipient, &receipt.recipient) {
        (
            arkret_models_collaboration::events_payloads::MlsWelcomeRecipient::Device {
                recipient_device_id,
            },
            arkret_models_crypto::RecipientMlsDurableSigner::Device {
                recipient_device_id: durable_recipient_device_id,
                ..
            },
        ) => {
            welcome.recipient_principal_id.as_ref() == Some(&receipt.recipient_principal_id)
                && recipient_device_id == durable_recipient_device_id
        }
        (
            arkret_models_collaboration::events_payloads::MlsWelcomeRecipient::NativeAgent {
                recipient_agent_id,
                recipient_agent_verification_method,
                agent_key_authorize_event_id,
            },
            arkret_models_crypto::RecipientMlsDurableSigner::NativeAgent {
                recipient_agent_id: durable_recipient_agent_id,
                recipient_agent_verification_method: durable_recipient_agent_verification_method,
                agent_key_authorize_event_id: durable_agent_key_authorize_event_id,
            },
        ) => {
            welcome.recipient_principal_id.as_ref() == Some(&receipt.recipient_principal_id)
                && recipient_agent_id == durable_recipient_agent_id
                && recipient_agent_verification_method
                    == durable_recipient_agent_verification_method
                && agent_key_authorize_event_id == durable_agent_key_authorize_event_id
        }
        (
            arkret_models_collaboration::events_payloads::MlsWelcomeRecipient::MinimalMetadataPairwise {
                recipient_pairwise_actor_id,
                recipient_pairwise_verification_method,
            },
            arkret_models_crypto::RecipientMlsDurableSigner::MinimalMetadataPairwise {
                recipient_pairwise_verification_method:
                    durable_recipient_pairwise_verification_method,
            },
        ) => {
            welcome.recipient_principal_id.is_none()
                && recipient_pairwise_actor_id == &receipt.recipient_principal_id
                && recipient_pairwise_verification_method
                    == durable_recipient_pairwise_verification_method
        }
        _ => false,
    }
}

fn projected_welcome_matches_consumer(
    row: &soland_domain::reducer::MlsWelcome,
    body: &KeyPackagesConsumeRequestBody,
) -> bool {
    let receipt = &body.recipient_durable_receipt;
    if row.recipient_actor_id != receipt.recipient_principal_id.as_str() {
        return false;
    }
    match &receipt.recipient {
        arkret_models_crypto::RecipientMlsDurableSigner::Device {
            recipient_device_id,
            ..
        } => {
            row.recipient_device_id.as_deref() == Some(recipient_device_id.as_str())
                && row.recipient_endpoint_verification_method.is_none()
        }
        arkret_models_crypto::RecipientMlsDurableSigner::NativeAgent {
            recipient_agent_verification_method,
            ..
        } => {
            row.recipient_device_id.is_none()
                && row.recipient_endpoint_verification_method.as_deref()
                    == Some(recipient_agent_verification_method.as_str())
                && row.intended_realm_id.is_none()
        }
        arkret_models_crypto::RecipientMlsDurableSigner::MinimalMetadataPairwise {
            recipient_pairwise_verification_method,
        } => {
            row.recipient_device_id.is_none()
                && row.recipient_endpoint_verification_method.as_deref()
                    == Some(recipient_pairwise_verification_method.as_str())
                && row.intended_realm_id.as_deref()
                    == Some(body.recipient_durable_receipt.realm_id.as_str())
        }
    }
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
                AppError::param_invalid(format!(
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
                        device_revocation_gate: None,
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
            && row.device_id.as_deref() == Some(device_id)
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
                device_revocation_gate: None,
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

async fn keypackage_device_revocation_gate(
    state: &AppState,
    actor_id: &str,
    device_id: &str,
    device_authorize_event_id: Option<&str>,
) -> Result<Option<soland_storage::DeviceRevocationGateSelector>, AppError> {
    let Some(device_authorize_event_id) = device_authorize_event_id else {
        return Ok(None);
    };
    let selector =
        crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state, actor_id, device_id,
        )
        .await
        .map_err(|_| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "KeyPackage device authorization is unavailable",
            )
            .with_wire_code("claim_failed")
        })?;
    if selector.target_device_authorize_event_id != device_authorize_event_id {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "KeyPackage device authorization is not current",
        )
        .with_wire_code("claim_failed"));
    }
    Ok(Some(selector))
}

fn validate_capabilities(capabilities: &[String]) -> Result<Vec<String>, String> {
    let capabilities_ref = capabilities.iter().map(String::as_str).collect::<Vec<_>>();
    arkret_models_crypto::validate_advertised_keypackage_capabilities(&capabilities_ref)
        .map_err(|_| "capabilities_invalid".to_owned())?;
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

async fn validate_agent_keypackage_upload(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
    authorize_event_id: &str,
    key_package_bytes: &[u8],
    signature: &KeyOperationSignature,
    signing_input: &[u8],
) -> Result<(), String> {
    verify_agent_keypackage_batch(
        state,
        principal,
        authorize_event_id,
        signature,
        signing_input,
    )
    .await?;
    validate_agent_keypackage_leaf(state, principal, authorize_event_id, key_package_bytes).await
}

async fn verify_agent_keypackage_batch(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
    authorize_event_id: &str,
    signature: &KeyOperationSignature,
    signing_input: &[u8],
) -> Result<(), String> {
    if !current_agent_key_authorization_matches(state, principal, authorize_event_id).await {
        return Err("claim_generation_mismatch".to_owned());
    }
    let accepted = state
        .event_queries()
        .accepted_event(authorize_event_id)
        .await
        .map_err(|_| "claim_generation_mismatch".to_owned())?
        .ok_or_else(|| "claim_generation_mismatch".to_owned())?;
    let event = serde_json::from_value::<arkret_wire::Event>(accepted.envelope)
        .map_err(|_| "claim_generation_mismatch".to_owned())?;
    if event.kind != arkret_wire::EventKind::AgentKeyAuthorize
        || event.actor_id.as_str() != principal.as_str()
    {
        return Err("claim_generation_mismatch".to_owned());
    }
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
    let agent = state
        .agent_pairings()
        .agent(principal.as_str())
        .await
        .map_err(|_| "claim_generation_mismatch".to_owned())?
        .ok_or_else(|| "claim_generation_mismatch".to_owned())?;
    let binding = agent
        .authorized_signing_key_binding
        .ok_or_else(|| "claim_generation_mismatch".to_owned())?;
    if binding.agent_key_authorize_event_id.as_str() != authorize_event_id
        || binding.core.verification_method.as_str() != verification_method
        || binding.core.public_key_digest.as_str() != expected_public_key_digest
    {
        return Err("claim_generation_mismatch".to_owned());
    }
    let public_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(binding.core.public_key.key.as_str())
        .map_err(|_| "claim_generation_mismatch".to_owned())?
        .as_slice()
        .try_into()
        .map_err(|_| "claim_generation_mismatch".to_owned())?;
    let actual_public_key_digest =
        arkret_signatures::agent_evidence::agent_signing_public_key_digest(&binding.public_key)
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

async fn validate_agent_keypackage_leaf(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
    authorize_event_id: &str,
    key_package_bytes: &[u8],
) -> Result<(), String> {
    let agent = state
        .agent_pairings()
        .agent(principal.as_str())
        .await
        .map_err(|_| "claim_generation_mismatch".to_owned())?
        .ok_or_else(|| "claim_generation_mismatch".to_owned())?;
    let binding = agent
        .authorized_signing_key_binding
        .ok_or_else(|| "claim_generation_mismatch".to_owned())?;
    if binding.agent_key_authorize_event_id.as_str() != authorize_event_id {
        return Err("claim_generation_mismatch".to_owned());
    }
    let public_key = URL_SAFE_NO_PAD
        .decode(binding.core.public_key.key.as_str())
        .map_err(|_| "claim_generation_mismatch".to_owned())?;
    validate_actor_keypackage_leaf(principal, &public_key, key_package_bytes)
}

#[cfg(test)]
fn validate_pairwise_keypackage_upload(
    principal: &arkret_wire::DidCoreId,
    verification_method: &arkret_wire::DidUrl,
    key_package_bytes: &[u8],
    signature: &KeyOperationSignature,
    signing_input: &[u8],
) -> Result<(), String> {
    verify_pairwise_keypackage_batch(principal, verification_method, signature, signing_input)?;
    validate_pairwise_keypackage_leaf(principal, verification_method, key_package_bytes)
}

fn pairwise_keypackage_public_key(
    principal: &arkret_wire::DidCoreId,
    verification_method: &arkret_wire::DidUrl,
) -> Result<[u8; 32], String> {
    arkret_models_crypto::MlsEndpointIdentity::minimal_metadata_pairwise(
        principal.clone(),
        verification_method.clone(),
    )
    .map_err(|_| "claim_generation_mismatch".to_owned())?;
    let controller = verification_method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(|| "claim_generation_mismatch".to_owned())?;
    let multibase = controller
        .strip_prefix("did:key:")
        .ok_or_else(|| "claim_generation_mismatch".to_owned())?;
    let public_key = arkret_canonical::decode_ed25519_multibase(multibase)
        .map_err(|_| "claim_generation_mismatch".to_owned())?;
    Ok(public_key)
}

fn verify_pairwise_keypackage_batch(
    principal: &arkret_wire::DidCoreId,
    verification_method: &arkret_wire::DidUrl,
    signature: &KeyOperationSignature,
    signing_input: &[u8],
) -> Result<(), String> {
    let public_key = pairwise_keypackage_public_key(principal, verification_method)?;
    if signature.kid.as_str() != verification_method.as_str()
        || signature
            .signature_algorithm
            .as_ref()
            .is_some_and(|algorithm| algorithm.as_str() != "Ed25519")
    {
        return Err("claim_generation_mismatch".to_owned());
    }
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &public_key,
        verification_method.as_str(),
        signing_input,
        signature,
    )
    .map_err(|_| "endpoint_signature_invalid".to_owned())
}

fn validate_pairwise_keypackage_leaf(
    principal: &arkret_wire::DidCoreId,
    verification_method: &arkret_wire::DidUrl,
    key_package_bytes: &[u8],
) -> Result<(), String> {
    let public_key = pairwise_keypackage_public_key(principal, verification_method)?;
    validate_actor_keypackage_leaf(principal, &public_key, key_package_bytes)
}

fn validate_actor_keypackage_leaf(
    principal: &arkret_wire::DidCoreId,
    public_key: &[u8],
    key_package_bytes: &[u8],
) -> Result<(), String> {
    let leaf = arkret_mls::author_leaf_from_key_package_bytes(key_package_bytes, 0)
        .map_err(|_| "key_package_invalid".to_owned())?;
    match leaf.credential {
        arkret_mls::AuthorLeafCredential::Basic { identity }
            if identity.as_slice() == principal.as_str().as_bytes() => {}
        _ => return Err("claim_generation_mismatch".to_owned()),
    }
    if leaf.signature_key.as_slice() != public_key {
        return Err("claim_generation_mismatch".to_owned());
    }
    Ok(())
}

async fn ensure_pairwise_realm_affinity(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
    verification_method: &arkret_wire::DidUrl,
    realm_id: &RealmId,
    expected_service_id: &str,
) -> Result<(), AppError> {
    arkret_models_crypto::MlsEndpointIdentity::minimal_metadata_pairwise(
        principal.clone(),
        verification_method.clone(),
    )
    .map_err(|_| AppError::capability_denied("pairwise endpoint binding is invalid"))?;
    let minimal_metadata_realm = state
        .realms()
        .realm_metadata(realm_id.as_str())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some_and(|record| record.minimal_metadata_realm);
    if !minimal_metadata_realm {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "pairwise endpoint requires the current minimal-metadata Realm profile",
        )
        .with_wire_code("claim_generation_mismatch"));
    }
    let snapshot = state.projections().snapshot();
    if snapshot
        .member(realm_id.as_str(), principal.as_str())
        .is_none_or(|membership| {
            membership.state != "join"
                || membership.recipient_service_id.as_deref() != Some(expected_service_id)
        })
    {
        return Err(AppError::new(
            ErrorCode::FailedPrecondition,
            "pairwise endpoint has no current Realm membership affinity",
        )
        .with_wire_code("claim_generation_mismatch"));
    }
    Ok(())
}

async fn validate_device_keypackage_leaf(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
    device_id: &str,
    key_package_bytes: &[u8],
) -> Result<(), String> {
    let device = state
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
            actor_id: principal.to_string(),
            device_id: device_id.to_owned(),
        })
        .await
        .map_err(|_| "claim_generation_mismatch".to_owned())?
        .ok_or_else(|| "claim_generation_mismatch".to_owned())?;
    if device.verification_state != "verified" || device.revoked_at.is_some() {
        return Err("claim_generation_mismatch".to_owned());
    }
    let device_public_key = device
        .payload
        .get("device_public_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "claim_generation_mismatch".to_owned())?;
    let verifying_key = crate::routing::identity::device_signing::decode_ed25519_key(
        device_public_key,
        "multibase",
    )
    .map_err(|_| "claim_generation_mismatch".to_owned())?;
    let leaf = arkret_mls::author_leaf_from_key_package_bytes(key_package_bytes, 0)
        .map_err(|_| "key_package_invalid".to_owned())?;
    match leaf.credential {
        arkret_mls::AuthorLeafCredential::Basic { identity }
            if identity.as_slice() == device_id.as_bytes() => {}
        _ => return Err("claim_generation_mismatch".to_owned()),
    }
    if leaf.signature_key.as_slice() != verifying_key.to_bytes() {
        return Err("claim_generation_mismatch".to_owned());
    }
    Ok(())
}

async fn verify_device_keypackage_signature(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
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
        .ok_or_else(|| AppError::param_invalid("authorized device signing key is unavailable"))?;
    if !crate::routing::identity::device_signature_kid_points_to_device_key(
        signature.kid.as_str(),
        principal.as_str(),
        device_public_key,
    ) {
        return Err(AppError::param_invalid(
            "KeyPackage signature kid does not point to the authorized device key",
        ));
    }
    let verifying_key = crate::routing::identity::device_signing::decode_ed25519_key(
        device_public_key,
        "multibase",
    )
    .map_err(|error| AppError::param_invalid(format!("device signing key is invalid: {error}")))?;
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &verifying_key.to_bytes(),
        signature.kid.as_str(),
        signing_input,
        signature,
    )
    .map_err(|_| AppError::param_invalid("device_signature_invalid"))
}

async fn current_device_authorization_matches(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
    device_id: &str,
    authorize_event_id: &str,
) -> bool {
    state
        .identities()
        .find_device(soland_services::identity::FindDeviceQuery {
            actor_id: principal.to_string(),
            device_id: device_id.to_owned(),
        })
        .await
        .ok()
        .flatten()
        .and_then(|device| device_authorize_trust_binding(&device))
        .and_then(|binding| binding.device_authorize_event_id)
        .as_deref()
        == Some(authorize_event_id)
}

async fn verify_session_keypackage_write_signature(
    state: &AppState,
    session: &SessionRecord,
    keypackage_refs: &[String],
    signature: &KeyOperationSignature,
    signing_input: &[u8],
) -> Result<(), AppError> {
    let principal = arkret_wire::DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::param_invalid(format!("invalid session principal: {error}")))?;
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
                .ok_or_else(|| AppError::param_invalid("KeyPackage signature target is missing"))?;
            if record.actor_id != session.actor
                || record.device_id.as_deref() != Some(session.device_id.as_str())
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
            .map_err(AppError::param_invalid)?;
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
    let capabilities_ref = capabilities.iter().map(String::as_str).collect::<Vec<_>>();
    arkret_models_crypto::validate_required_keypackage_capabilities(
        &capabilities_ref,
        &capabilities_ref,
    )
    .map_err(|_| AppError::param_invalid("required_capabilities is invalid or unsupported"))?;
    Ok(capabilities.iter().cloned().collect())
}

fn capabilities_satisfy(published: &[String], required: &BTreeSet<String>) -> bool {
    let published: BTreeSet<_> = published.iter().cloned().collect();
    required.is_subset(&published)
}

async fn current_agent_keypackage_trust_binding(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
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
        || event.actor_id.as_str() != principal.as_str()
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
    principal: &arkret_wire::DidCoreId,
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

pub(crate) async fn current_agent_key_authorization_matches_method(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
    authorize_event_id: &str,
    verification_method: &str,
) -> bool {
    if !current_agent_key_authorization_matches(state, principal, authorize_event_id).await {
        return false;
    }
    state
        .agent_pairings()
        .agent(principal.as_str())
        .await
        .ok()
        .flatten()
        .and_then(|agent| agent.authorized_verification_method)
        .as_deref()
        == Some(verification_method)
}

async fn current_keypackage_trust_binding(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
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
    principal: &arkret_wire::DidCoreId,
    target_device_ids: &BTreeSet<String>,
    intended_realm_id: Option<&str>,
    pairwise_verification_method: Option<&str>,
) -> Result<KeyPackageTrustSelector, AppError> {
    if let Some(verification_method) = pairwise_verification_method {
        let realm_id = intended_realm_id.ok_or_else(|| {
            AppError::new(
                ErrorCode::FailedPrecondition,
                "pairwise claim requires Realm affinity",
            )
            .with_wire_code("claim_generation_mismatch")
        })?;
        let method = arkret_wire::DidUrl::new(verification_method.to_owned())
            .map_err(|_| AppError::param_invalid("pairwise verification method is invalid"))?;
        let realm = RealmId::new(realm_id.to_owned())
            .map_err(|_| AppError::param_invalid("pairwise Realm id is invalid"))?;
        ensure_pairwise_realm_affinity(state, principal, &method, &realm, state.service_id())
            .await?;
        return Ok(KeyPackageTrustSelector::MinimalMetadataPairwise {
            verification_method: verification_method.to_owned(),
            intended_realm_id: realm_id.to_owned(),
        });
    }
    if let Some(binding) = current_agent_keypackage_trust_binding(state, principal).await? {
        if let Some(realm_id) = intended_realm_id {
            let agent = state
                .agent_pairings()
                .agent(principal.as_str())
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| {
                    AppError::new(
                        ErrorCode::FailedPrecondition,
                        "Native Agent membership is unavailable",
                    )
                    .with_wire_code("claim_generation_mismatch")
                })?;
            crate::routing::identity::managed_agent_pcr::validate_effective_agent_realm_membership(
                state,
                &agent,
                realm_id,
                now(),
            )
            .await
            .map_err(|_| {
                AppError::new(
                    ErrorCode::FailedPrecondition,
                    "Native Agent is not an effective Realm member",
                )
                .with_wire_code("claim_generation_mismatch")
            })?;
        }
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
    device_id: Option<&str>,
    reason_code: impl AsRef<str>,
) -> KeypackageFailure {
    let keypackage_ref = if entry.keypackage_ref.is_empty() {
        entry.keypackage_id.clone()
    } else {
        entry.keypackage_ref.clone()
    };
    KeypackageFailure {
        keypackage_ref: (!keypackage_ref.is_empty()).then_some(keypackage_ref),
        device_id: device_id.map(str::to_owned),
        reason_code: keypackage_reason_code(reason_code.as_ref()),
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
        reason_code: keypackage_reason_code(reason_code.as_ref()),
        retry_after_ms: None,
    }
}

fn keypackage_reason_code(reason_code: &str) -> arkret_wire::ReasonCode {
    if arkret_wire::ReasonCode::is_valid_wire(reason_code) {
        arkret_wire::ReasonCode::from_wire(reason_code)
    } else {
        // The failure DTO has a closed lexical profile. A diagnostic string
        // must never make the whole batch outcome fail JSON serialization and
        // turn a per-entry rejection into HTTP 500.
        arkret_wire::ReasonCode::from_wire("key_package_invalid")
    }
}

fn non_empty_keypackage_refs(refs: &[String]) -> Result<Vec<String>, AppError> {
    if refs.is_empty() {
        return Err(AppError::param_missing("key_package_refs is required"));
    }
    Ok(refs.to_vec())
}

fn consume_group_ref(body: &KeyPackagesConsumeRequestBody) -> String {
    body.recipient_durable_receipt.mls_group_id.to_string()
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
    let Ok(principal) = arkret_wire::DidCoreId::new(actor_id.to_owned()) else {
        return false;
    };
    let target_device_ids = BTreeSet::new();
    // This is the admission preflight for the membership transition which
    // establishes the Agent's effective Realm membership. Requiring that
    // membership inside the trust selector would make the first join
    // impossible. The accepted Agent-key authorization is still checked
    // here, and the KeyPackage's Realm binding is checked below; actual claim
    // paths continue to pass `Some(intended_realm_id)` and recheck effective
    // membership at commit time.
    let Ok(trust_selector) =
        current_keypackage_claim_trust_selector(state, &principal, &target_device_ids, None, None)
            .await
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
        && (target_device_ids.is_empty()
            || kp
                .device_id
                .as_ref()
                .is_some_and(|device_id| target_device_ids.contains(device_id)))
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

async fn keypackage_claim_record(
    state: &AppState,
    record: &MlsKeyPackageRow,
    claim_request_id: &str,
) -> Result<KeyPackageClaimRecord, AppError> {
    let principal_id = arkret_wire::DidCoreId::new(record.actor_id.clone())
        .map_err(|error| AppError::internal(format!("invalid principal_id: {error}")))?;
    let pairwise_verification_method = if record.device_authorize_event_id.is_none()
        && record.agent_key_authorize_event_id.is_none()
    {
        record
            .endpoint_verification_method
            .clone()
            .map(arkret_wire::DidUrl::new)
            .transpose()
            .map_err(|error| AppError::internal(format!("pairwise method invalid: {error}")))?
    } else {
        None
    };
    let trust_binding = if pairwise_verification_method.is_none() {
        Some(trust_binding_from_row(record)?)
    } else {
        None
    };
    let (device_id, agent_id, agent_verification_method) = if trust_binding
        .as_ref()
        .and_then(|binding| binding.agent_key_authorize_event_id.as_ref())
        .is_some()
    {
        let agent = state
            .agent_pairings()
            .agent(principal_id.as_str())
            .await
            .map_err(|error| AppError::internal(format!("target Agent lookup failed: {error}")))?
            .ok_or_else(|| AppError::internal("target Agent projection is unavailable"))?;
        let method = agent
            .authorized_verification_method
            .ok_or_else(|| AppError::internal("target Agent verification method is unavailable"))?;
        let method = arkret_wire::DidUrl::new(method).map_err(|error| {
            AppError::internal(format!("target Agent verification method invalid: {error}"))
        })?;
        (None, Some(principal_id.clone()), Some(method))
    } else {
        (
            record
                .device_id
                .clone()
                .map(arkret_wire::DeviceId::new)
                .transpose()
                .map_err(|error| AppError::internal(format!("invalid device_id: {error}")))?,
            None,
            None,
        )
    };
    let keypackage = URL_SAFE_NO_PAD.encode(&record.key_package_bytes);
    let mut claim_id_preimage = b"ak.keypackage.claim_id.v1".to_vec();
    claim_id_preimage.push(0);
    claim_id_preimage.extend(record.id.as_bytes());
    claim_id_preimage.push(0);
    claim_id_preimage.extend(claim_request_id.as_bytes());
    let claim_id = format!(
        "claim-{}",
        URL_SAFE_NO_PAD.encode(arkret_canonical::sha256_digest(claim_id_preimage))
    );
    Ok(KeyPackageClaimRecord {
        claim_id,
        keypackage_ref: record.keypackage_ref.clone(),
        principal_id,
        device_id,
        agent_id,
        agent_verification_method,
        pairwise_verification_method,
        keypackage,
        capabilities: record.capabilities.clone(),
        device_authorize_event_id: trust_binding
            .as_ref()
            .and_then(|binding| binding.device_authorize_event_id.clone())
            .map(arkret_wire::EventId::new)
            .transpose()
            .map_err(|error| {
                AppError::internal(format!("device authorization Event id invalid: {error}"))
            })?,
        agent_key_authorize_event_id: trust_binding
            .as_ref()
            .and_then(|binding| binding.agent_key_authorize_event_id.clone())
            .map(arkret_wire::EventId::new)
            .transpose()
            .map_err(|error| {
                AppError::internal(format!("Agent authorization Event id invalid: {error}"))
            })?,
        expires_at: match record.claim_expires_at_unix_ms {
            Some(expires_at_unix_ms) => unix_millis_datetime(expires_at_unix_ms)?,
            None => unix_timestamp_datetime(record.lifetime_not_after)?,
        },
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
    use serde_json::json;

    use super::*;

    fn pairwise_endpoint(seed: [u8; 32]) -> (arkret_wire::DidCoreId, arkret_wire::DidUrl) {
        let key = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&key);
        (
            arkret_wire::DidCoreId::new(format!("ak:did_core:key:{multibase}")).unwrap(),
            arkret_wire::DidUrl::new(format!("did:key:{multibase}#{multibase}")).unwrap(),
        )
    }

    #[test]
    fn upload_failure_carries_only_a_real_device_selector() {
        let entry = KeyPackageUploadEntry {
            keypackage_id: "kp-fixture".to_owned(),
            keypackage_ref: format!("sha256:{}", "1".repeat(64)),
            keypackage: arkret_wire::Base64UrlString::new("AA").unwrap(),
            cipher_suites: vec!["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned()],
            capabilities: vec!["ak.content.v1".to_owned()],
            expires_at: now() + chrono::Duration::minutes(5),
            created_at: now(),
            last_resort: None,
        };

        let pairwise_failure = keypackage_failure(&entry, None, "schema_violation");
        assert!(pairwise_failure.device_id.is_none());
        let device_failure = keypackage_failure(
            &entry,
            Some("ak:device:01964137-0000-7000-8000-000000000001"),
            "schema_violation",
        );
        assert_eq!(
            device_failure.device_id.as_deref(),
            Some("ak:device:01964137-0000-7000-8000-000000000001")
        );
    }

    #[test]
    fn last_resort_consume_rejects_cross_claim_coordinate_substitution() {
        let claims = [("claim-a", "kp-ref")];
        assert!(last_resort_claim_coordinates_match(
            "request-a",
            "request-a",
            claims,
            "claim-a",
            "kp-ref",
        ));
        assert!(!last_resort_claim_coordinates_match(
            "request-a",
            "request-b",
            claims,
            "claim-a",
            "kp-ref",
        ));
        assert!(!last_resort_claim_coordinates_match(
            "request-a",
            "request-a",
            claims,
            "claim-b",
            "kp-ref",
        ));
    }

    #[test]
    fn native_agent_binding_is_an_exclusive_branch() {
        let event_id = "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let binding =
            trust_binding_from_parts(None, Some(event_id.to_owned()), None, None, "invalid")
                .unwrap();
        assert_eq!(
            binding.agent_key_authorize_event_id.as_deref(),
            Some(event_id)
        );
        assert!(trust_binding_from_parts(None, None, None, None, "invalid").is_err());
        assert!(
            trust_binding_from_parts(
                Some(event_id.to_owned()),
                Some(event_id.to_owned()),
                None,
                None,
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
        let principal =
            arkret_identifiers::DidFullId::new("did:web:agent.example".to_owned()).unwrap();
        let principal_core = arkret_wire::project_full_id_to_core_id(&principal).unwrap();
        let verification_method = "did:web:agent.example#runtime-1";
        let signing_seed = [17_u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
        let public_key_digest = arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(
            signing_key.verifying_key().to_bytes(),
        ))
        .unwrap();
        let realm_id = arkret_identifiers::RealmId::new(
            "ak:realm:AYKC0LicsGtFBq78orvaQecIZl8Bxv9zAaV4Eg66tdIr".to_owned(),
        )
        .unwrap();
        let authorize_event = crate::test_event::raw_event(
            arkret_wire::EventKind::AgentKeyAuthorize.as_str(),
            arkret_wire::ScopeRef::Realm { realm_id },
            principal_core.clone(),
            1,
            arkret_identifiers::Hlc::new("019041000000-0001-0000000f").unwrap(),
            json!({
                "agent_id": principal_core.as_str(),
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
        let authorize_canonical_digest = authorize_event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        state
            .event_queries()
            .store_canonical_event(soland_services::events::AcceptedEvent {
                event_id: authorize_event_id.clone(),
                actor_id: principal.to_string(),
                actor_seq: 1,
                realm_id: Some(authorize_event.realm_id.to_string()),
                kind: arkret_wire::EventKind::AgentKeyAuthorize
                    .as_str()
                    .to_owned(),
                schema_id: "ak.schema.event.v1".to_owned(),
                digest_suite: arkret_canonical::DigestSuite::Sha256,
                canonical_digest: authorize_canonical_digest,
                canonical_bytes: authorize_canonical_bytes,
                envelope: authorize_envelope,
                received_at: now(),
            })
            .await
            .unwrap();

        let mut agent = soland_services::identity::AgentPairingState::new(
            principal_core.to_string(),
            "ak:did_core:web:alice.example".to_owned(),
            authorize_event.realm_id.to_string(),
            arkret_wire::DidUrl::new("did:web:alice.example#managed-controller").unwrap(),
            AgentLifecycleState::Active,
            now(),
        );
        let signing_key_binding = serde_json::from_value(json!({
            "schema": "ak.schema.agent_signing_key_binding.v1",
            "agent_id": principal_core.as_str(),
            "agent_key_id": "ak:agent_key:01904100-0000-7000-8000-00000000000f",
            "verification_method": verification_method,
            "public_key": {
                "kty": "OKP",
                "algorithm": "Ed25519",
                "key": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes())
            },
            "public_key_digest": public_key_digest.as_str(),
            "agent_key_authorize_event_id": authorize_event_id,
            "issued_at": "2026-01-01T00:00:00.000Z",
            "controller_id": "ak:did_core:web:alice.example",
            "controller_proof": {
                "kind": "controller_signature",
                "verification_method": "did:web:alice.example#managed-controller",
                "jws": "proof"
            }
        }))
        .unwrap();
        agent.authorized_event_ref = Some(authorize_event_id.clone());
        agent.authorized_verification_method = Some(verification_method.to_owned());
        agent.authorized_public_key_digest = Some(public_key_digest.to_string());
        agent.authorized_signing_key_binding = Some(signing_key_binding);
        state.agent_pairings().save_agent(agent).await.unwrap();

        let mut authorize_projection = arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-00000000000f",
            )
            .unwrap(),
            authorize_event.realm_id.clone(),
            arkret_wire::EventKind::AgentKeyAuthorize,
            json!({
                "agent_id": principal_core.as_str(),
                "key_id": "ak:agent_key:01904100-0000-7000-8000-00000000000f",
                "verification_method": verification_method,
            }),
        );
        let authorize_projection_event_id =
            arkret_wire::EventId::new(authorize_event_id.clone()).unwrap();
        authorize_projection.context.event_id = authorize_projection_event_id.clone();
        authorize_projection.context.accepted_event_id = authorize_projection_event_id;
        let effect = state
            .test_projection()
            .lock()
            .apply(&authorize_projection, state.hlc());
        assert!(matches!(
            effect,
            soland_domain::reducer::ProjectionEffect::AgentKeyAuthorizeProjected { .. }
        ));

        let identity = arkret_mls::ArkretMlsIdentity::new_native_agent(
            principal_core.clone(),
            arkret_wire::DidUrl::new(verification_method.to_owned()).unwrap(),
            arkret_wire::EventId::new(authorize_event_id.clone()).unwrap(),
            arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(
                ed25519_dalek::SigningKey::from_bytes(&signing_seed),
            ),
        )
        .unwrap();
        let record = identity.key_package_record().unwrap();
        let key_package_bytes = URL_SAFE_NO_PAD.decode(record.keypackage.as_str()).unwrap();
        let upload = identity
            .signed_key_packages_upload_request(&[record], verification_method, None)
            .unwrap();
        let signing_input =
            arkret_models_crypto::http_bodies::keypackages_upload_signing_input(&upload.unsigned())
                .unwrap();

        validate_agent_keypackage_upload(
            &state,
            &principal_core,
            &authorize_event_id,
            &key_package_bytes,
            &upload.endpoint_signature,
            &signing_input,
        )
        .await
        .unwrap();
    }

    #[test]
    fn pairwise_keypackage_upload_binds_outer_signature_leaf_actor_and_leaf_key() {
        let seed = [19_u8; 32];
        let (pairwise_actor, method) = pairwise_endpoint(seed);
        let identity = arkret_mls::ArkretMlsIdentity::new_minimal_metadata_pairwise(
            pairwise_actor.clone(),
            method.clone(),
            arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(
                ed25519_dalek::SigningKey::from_bytes(&seed),
            ),
        )
        .unwrap();
        let record = identity.key_package_record().unwrap();
        let realm_id = arkret_wire::RealmId::new(
            "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5".to_owned(),
        )
        .unwrap();
        let upload = identity
            .signed_key_packages_upload_request(
                std::slice::from_ref(&record),
                method.as_str(),
                Some(realm_id),
            )
            .unwrap();
        assert_eq!(upload.principal_id, pairwise_actor);
        let key_package_bytes = URL_SAFE_NO_PAD.decode(record.keypackage.as_str()).unwrap();
        let signing_input =
            arkret_models_crypto::http_bodies::keypackages_upload_signing_input(&upload.unsigned())
                .unwrap();
        validate_pairwise_keypackage_upload(
            &upload.principal_id,
            &method,
            &key_package_bytes,
            &upload.endpoint_signature,
            &signing_input,
        )
        .unwrap();

        let other_seed = [23_u8; 32];
        let (other_actor, other_method) = pairwise_endpoint(other_seed);
        let other_identity = arkret_mls::ArkretMlsIdentity::new_minimal_metadata_pairwise(
            other_actor,
            other_method,
            arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(
                ed25519_dalek::SigningKey::from_bytes(&other_seed),
            ),
        )
        .unwrap();
        let other_record = other_identity.key_package_record().unwrap();
        let other_bytes = URL_SAFE_NO_PAD
            .decode(other_record.keypackage.as_str())
            .unwrap();
        assert_eq!(
            validate_pairwise_keypackage_upload(
                &upload.principal_id,
                &method,
                &other_bytes,
                &upload.endpoint_signature,
                &signing_input,
            ),
            Err("claim_generation_mismatch".to_owned())
        );
    }

    #[test]
    fn repeated_consumed_query_accepts_only_the_exact_durable_winner() {
        let receipt = json!({"domain": "ak.keypackage.consume_receipt.v1"});
        assert!(consumed_query_source_winner_matches(
            "consumed",
            "sha256:request",
            Some(&receipt),
            "sha256:request",
            &receipt,
        ));
        assert!(!consumed_query_source_winner_matches(
            "consumed",
            "sha256:request",
            Some(&receipt),
            "sha256:other",
            &receipt,
        ));
        assert!(!consumed_query_source_winner_matches(
            "last_resort_claimed",
            "sha256:request",
            Some(&receipt),
            "sha256:request",
            &receipt,
        ));
    }

    #[test]
    fn welcome_accepts_active_single_use_and_last_resort_claim_audits_only() {
        assert!(peer_claim_state_allows_welcome("claimed"));
        assert!(peer_claim_state_allows_welcome("last_resort_claimed"));
        assert!(!peer_claim_state_allows_welcome("consumed"));
        assert!(!peer_claim_state_allows_welcome("expired"));
        assert!(!peer_claim_state_allows_welcome("revoked"));
    }

    #[test]
    fn terminal_query_requires_exact_refs_and_non_early_expiry() {
        assert!(terminal_claim_coordinates_match(
            "expired",
            20_500,
            20_500,
            ["kp-a", "kp-b"],
            ["kp-a", "kp-b"],
        ));
        assert!(!terminal_claim_coordinates_match(
            "expired",
            20_500,
            20_499,
            ["kp-a", "kp-b"],
            ["kp-a", "kp-b"],
        ));
        assert!(!terminal_claim_coordinates_match(
            "expired",
            20_500,
            20_500,
            ["kp-b", "kp-a"],
            ["kp-a", "kp-b"],
        ));
        assert!(terminal_claim_coordinates_match(
            "revoked",
            20_500,
            19_000,
            ["kp-a"],
            ["kp-a"],
        ));
    }

    #[test]
    fn claim_failed_query_rejects_a_contradictory_existing_winner() {
        let expected = PeerKeyPackageClaimLedgerRecord {
            source_service_id: "did:web:source.example".to_owned(),
            claim_request_id: "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            request_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            key_package_use: "none".to_owned(),
            keypackage_id: None,
            outcome: None,
            terminal_receipt: Some(json!({"terminal_state": "never_claimed"})),
            consume_receipt: None,
            claim_expires_at_unix_ms: Some(20_500),
            expires_at: 620,
            state: "claim_failed".to_owned(),
            updated_at: 10,
        };
        let mut replay = expected.clone();
        replay.updated_at = 11;
        assert!(claim_failed_source_winner_matches(&replay, &expected));

        let mut contradictory = expected.clone();
        contradictory.key_package_use = "last_resort".to_owned();
        contradictory.state = "last_resort_claimed".to_owned();
        contradictory.outcome = Some(json!({"claims": ["kp-a"]}));
        assert!(!claim_failed_source_winner_matches(
            &contradictory,
            &expected
        ));
    }

    #[test]
    fn keypackage_failure_reason_never_breaks_the_typed_outcome() {
        assert_eq!(
            keypackage_reason_code("claim_generation_mismatch").as_str(),
            "claim_generation_mismatch"
        );
        assert_eq!(
            keypackage_reason_code("param_invalid: claim generation mismatch").as_str(),
            "key_package_invalid"
        );
    }
}
