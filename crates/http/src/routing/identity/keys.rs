//! E2EE key surfaces.
//!
//! Surfaces:
//! - `POST /_arkret/self/keys/upload` - upload one-time / fallback prekeys with the current device
//!   signature.
//! - `POST /_arkret/self/keys/query` - fetch device key bundles for a peer set.
//! - `POST /_arkret/self/keys/claim` - claim one-time keys, draining the per-device pool.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::Signature;
use salvo::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};
use soland_application::identity::{DeviceIdentity, FindDeviceQuery, SaveDeviceCommand};
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};

use super::{bearer_token, is_device_revoked, now, sha256_hex};
use crate::extract::JsonBody;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{
    AuthorizedDeviceSigningKey, DeviceSigningKeyDirectoryOutcome,
    DeviceSigningKeyDirectoryQueryRequestBody, DeviceStatus, KeysClaimOutcome,
    KeysClaimRequestBody, KeysQueryOutcome, KeysQueryRequestBody, KeysUploadOutcome,
    KeysUploadRequestBody, QueryDeviceRecord,
};

const KEYS_UPLOAD_SIGNATURE_PREFIX: &[u8] = b"ak.keys-upload-v1\n";

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("keys/upload").post(keys_upload))
        .push(Router::with_path("keys/query").post(keys_query))
        .push(Router::with_path("keys/claim").post(keys_claim))
}

/// Product-surface (`/_soland/gate/account/...`) router carrying the
/// server-to-server device signing-key directory read used by the Auth Server
/// (coauth) to verify device holder proofs. Mounted under `_soland`, not the
/// `/_arkret` protocol root: it is a deployment-local integration read, not a
/// spec operation.
pub(super) fn product_router() -> Router {
    Router::with_path("gate/account/device-signing-keys/query").post(device_signing_keys_query)
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.upload.create"))]
async fn keys_upload(
    aa: AuthArgs,
    body: JsonBody<KeysUploadRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysUploadOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    if is_device_revoked(state, &session.actor, &session.device_id).await {
        return Err(AppError::unauthenticated("device revoked"));
    }

    let body = body.into_inner();
    let device_id = body.device_id.as_str().to_owned();
    if device_id != session.device_id {
        return Err(AppError::capability_denied(
            "session device does not match upload device",
        ));
    }
    let current_device = state
        .identity_application()
        .find_device(FindDeviceQuery {
            actor_id: session.actor.clone(),
            device_id: device_id.clone(),
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let current_facet =
        crate::routing::identity::cross_signing::resolve_device_signing_directory_facet(
            state,
            &session.actor,
            &device_id,
        )
        .await;
    if !matches!(current_facet.status, DeviceStatus::Active) {
        return Err(AppError::capability_denied(
            "device is revoked, unverified, or fenced by the current generation",
        )
        .with_wire_code("device_generation_fenced"));
    }
    verify_keys_upload_device_signature(
        &session.actor,
        &device_id,
        current_device.as_ref(),
        &body.one_time_keys,
        &body.fallback_keys,
        &body.device_signature,
    )?;

    let one_time_key_count = body.one_time_keys.len() as u64;
    let mut one_time_key_alg_counts = BTreeMap::new();
    for key_id in body.one_time_keys.keys() {
        let algorithm = key_id.as_str().split(':').next().unwrap_or(key_id.as_str());
        *one_time_key_alg_counts
            .entry(
                arkret_wire::NonEmptyString::new(algorithm.to_owned()).map_err(|error| {
                    AppError::invalid_param(format!("one-time key algorithm is invalid: {error}"))
                })?,
            )
            .or_insert(0) += 1;
    }
    let one_time_keys = body.one_time_keys;
    let fallback_keys = body.fallback_keys;
    let key_payload = json!({
        "device_id": device_id.clone(),
        "one_time_keys": one_time_keys.clone(),
        "fallback_keys": fallback_keys.clone(),
        "device_signature": body.device_signature.clone(),
        "updated_at": now(),
    });
    if let Err(error) = state
        .key_material_application()
        .save_bundle(
            session.actor.clone(),
            device_id.clone(),
            key_payload.clone(),
        )
        .await
    {
        tracing::error!(%error, "failed to persist device keys");
    }

    let updated_at = now();
    let previous_payload = current_device
        .as_ref()
        .map(|device| device.payload.clone())
        .unwrap_or_else(|| json!({"device_id": device_id.clone()}));
    let mut device_payload = previous_payload.clone();
    if let Some(map) = device_payload.as_object_mut() {
        map.insert("device_id".to_owned(), Value::String(device_id.clone()));
        map.insert(
            "display_name".to_owned(),
            current_device
                .as_ref()
                .and_then(|device| device.display_name.clone())
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert(
            "verification".to_owned(),
            Value::String(
                current_device
                    .as_ref()
                    .map(|device| device.verification_state.clone())
                    .unwrap_or_else(|| "unverified".to_owned()),
            ),
        );
        map.insert("last_key_upload_at".to_owned(), json!(updated_at));
        map.insert("inventory".to_owned(), previous_payload.clone());
    }
    let device = DeviceIdentity {
        actor_id: session.actor.clone(),
        device_id: device_id.clone(),
        display_name: current_device
            .as_ref()
            .and_then(|device| device.display_name.clone()),
        verification_state: current_device
            .as_ref()
            .map(|device| device.verification_state.clone())
            .unwrap_or_else(|| "unverified".to_owned()),
        payload: device_payload,
        created_at: current_device
            .as_ref()
            .map(|device| device.created_at)
            .unwrap_or(updated_at),
        updated_at,
        revoked_at: None,
    };
    state
        .identity_application()
        .save_device(SaveDeviceCommand {
            actor_id: session.actor.clone(),
            device_id: device_id.clone(),
            display_name: device.display_name.clone(),
            device,
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    if let Err(error) = state
        .key_material_application()
        .save_one_time_keys(
            session.actor,
            device_id,
            one_time_keys
                .into_values()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| AppError::internal(format!("serialize one-time key: {error}")))?,
        )
        .await
    {
        tracing::error!(%error, "failed to persist one-time keys");
    }

    one_time_key_alg_counts.insert(
        arkret_wire::NonEmptyString::new("total").expect("total is non-empty"),
        one_time_key_count,
    );
    json_ok(KeysUploadOutcome {
        one_time_key_counts: one_time_key_alg_counts,
        fallback_keys,
    })
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.query.lookup"))]
async fn keys_query(
    aa: AuthArgs,
    body: JsonBody<KeysQueryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;

    let body = body.into_inner();
    let mut result = BTreeMap::new();
    let mut cross_signing = BTreeMap::new();
    let mut device_generations = BTreeMap::new();
    for (actor, devices) in body.device_keys {
        if !keys_query_actor_visible_to_requester(state, &session.actor, actor.as_str()) {
            continue;
        }
        // Tier-2 (device-lifecycle.md §8.2): attach this principal's current
        // accepted cross_signing.publish payload so the client can DID-anchor
        // the SSK before trusting any per-device binding. Inserted once per
        // principal, only when a publish is accepted.
        if let Some(publish) =
            crate::routing::identity::cross_signing::resolve_current_cross_signing_publish(
                state,
                actor.as_str(),
            )
        {
            cross_signing.insert(actor.clone(), publish);
        }
        if let Some(generation) =
            crate::routing::identity::device_generation::current_device_generation(
                state,
                actor.as_str(),
            )
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
        {
            device_generations.insert(
                actor.clone(),
                arkret_models_crypto::keys::DeviceGenerationState {
                    current_device_generation_ref: arkret_wire::NonEmptyString::new(
                        generation.current_ref,
                    )
                    .map_err(|error| {
                        AppError::internal(format!("stored device generation is invalid: {error}"))
                    })?,
                    device_generation_status: match generation.status {
                        crate::routing::identity::device_generation::DeviceGenerationStatus::Active => {
                            arkret_models_crypto::keys::DeviceGenerationStatus::Active
                        }
                        crate::routing::identity::device_generation::DeviceGenerationStatus::Conflicted => {
                            arkret_models_crypto::keys::DeviceGenerationStatus::Conflicted
                        }
                    },
                },
            );
        }
        let mut actor_keys = BTreeMap::new();
        for device_id in devices {
            let device_record = state
                .identity_application()
                .find_device(FindDeviceQuery {
                    actor_id: actor.as_str().to_owned(),
                    device_id: device_id.as_str().to_owned(),
                })
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            if device_record.is_none() {
                continue;
            }
            // Revocation filter (device-lifecycle.md §8.2): a revoked device is
            // omitted entirely, so its prekey bundle is never surfaced and no
            // signing key leaks.
            // Carry the opaque uploaded prekey blob under `algorithms`. The demo
            // upload stores one payload object per device, so it is surfaced as a
            // single `algorithms` map (key→value) rather than per-algorithm
            // key_records; the directory facet below is the real signing-key data.
            let mut algorithms = match state
                .key_material_application()
                .bundle(actor.as_str(), device_id.as_str())
                .await
            {
                Ok(Some(value)) => value
                    .get("one_time_keys")
                    .cloned()
                    .and_then(|value| serde_json::from_value(value).ok())
                    .unwrap_or_default(),
                _ => BTreeMap::new(),
            };
            // Signing-key directory facet from the authoritative devices-table
            // `payload.device_public_key`: returns the verify key only for a
            // verified, non-revoked device. Shared with the recovery receipt
            // predicate via `resolve_device_signing_directory_facet`.
            let facet =
                crate::routing::identity::cross_signing::resolve_device_signing_directory_facet(
                    state,
                    actor.as_str(),
                    device_id.as_str(),
                )
                .await;
            if !matches!(facet.status, DeviceStatus::Active) {
                algorithms.clear();
            }
            actor_keys.insert(
                device_id,
                QueryDeviceRecord {
                    algorithms,
                    device_signing_key: facet
                        .signing_key_did
                        .map(arkret_wire::DidKey::new)
                        .transpose()
                        .map_err(|error| {
                            AppError::internal(format!(
                                "stored device signing key is invalid: {error}"
                            ))
                        })?,
                    hpke_key: facet
                        .hpke_key
                        .map(arkret_wire::NonEmptyString::new)
                        .transpose()
                        .map_err(|error| {
                            AppError::internal(format!("stored HPKE key is invalid: {error}"))
                        })?,
                    trust_algorithms: facet
                        .trust_algorithms
                        .map(|algorithms| {
                            algorithms
                                .into_iter()
                                .map(arkret_wire::NonEmptyString::new)
                                .collect::<Result<Vec<_>, _>>()
                        })
                        .transpose()
                        .map_err(|error| {
                            AppError::internal(format!(
                                "stored trust algorithm is invalid: {error}"
                            ))
                        })?,
                    device_status: Some(facet.status),
                    cross_signing_binding: facet.cross_signing_binding,
                    enrollment_authority_binding: facet.enrollment_authority_binding,
                    device_authorize_event_id: facet.device_authorize_event_id,
                    authorized_generation_ref: facet.authorized_generation_ref,
                },
            );
        }
        result.insert(actor, actor_keys);
    }
    json_ok(KeysQueryOutcome {
        device_keys: result,
        failures: Vec::new(),
        cross_signing,
        device_generations,
    })
}

fn keys_query_actor_visible_to_requester(state: &AppState, requester: &str, actor: &str) -> bool {
    if requester == actor {
        return true;
    }
    let Ok(requester_did) = arkret_identifiers::Did::new(requester.to_owned()) else {
        return false;
    };
    let Ok(actor_did) = arkret_identifiers::Did::new(actor.to_owned()) else {
        return false;
    };
    state
        .realm_directory_application()
        .snapshot()
        .entries_iter()
        .any(|(_, entry)| {
            entry.members.contains(&requester_did) && entry.members.contains(&actor_did)
        })
}

fn keys_upload_signing_input(
    device_id: &str,
    one_time_keys: &impl Serialize,
    fallback_keys: &impl Serialize,
) -> Result<Vec<u8>, AppError> {
    let body = json!({
        "device_id": device_id,
        "one_time_keys": one_time_keys,
        "fallback_keys": fallback_keys,
    });
    let canonical = arkret_canonical::canonical_json_bytes(&body)
        .map_err(|error| AppError::invalid_param(format!("keys/upload canonicalize: {error}")))?;
    let mut input = Vec::with_capacity(KEYS_UPLOAD_SIGNATURE_PREFIX.len() + canonical.len());
    input.extend_from_slice(KEYS_UPLOAD_SIGNATURE_PREFIX);
    input.extend_from_slice(&canonical);
    Ok(input)
}

fn verification_method_controller(verification_method: &str) -> &str {
    let no_query = verification_method
        .split_once('?')
        .map(|(head, _)| head)
        .unwrap_or(verification_method);
    no_query
        .split_once('#')
        .map(|(head, _)| head)
        .unwrap_or(no_query)
}

pub(crate) fn device_signature_kid_points_to_device_key(
    kid: &str,
    actor: &str,
    device_public_key: &str,
) -> bool {
    let expected_did_key = format!("did:key:{device_public_key}");
    kid == expected_did_key
        || kid
            .strip_prefix(&expected_did_key)
            .is_some_and(|rest| rest.starts_with('#') || rest.starts_with('?'))
        || verification_method_controller(kid) == actor
}

fn verify_keys_upload_device_signature(
    actor: &str,
    device_id: &str,
    current_device: Option<&DeviceIdentity>,
    one_time_keys: &impl Serialize,
    fallback_keys: &impl Serialize,
    device_signature: &arkret_models_crypto::artifacts_keys::KeyOperationSignature,
) -> Result<(), AppError> {
    let record = current_device.ok_or_else(|| {
        AppError::invalid_param("keys/upload requires an authorized device_public_key")
    })?;
    if record.verification_state != "verified" || record.revoked_at.is_some() {
        return Err(AppError::invalid_param(
            "keys/upload requires a verified, non-revoked device",
        ));
    }
    let device_public_key = record
        .payload
        .get("device_public_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::invalid_param("keys/upload requires authoritative device_public_key")
        })?;
    let alg = device_signature
        .alg
        .as_ref()
        .map(arkret_wire::NonEmptyString::as_str)
        .unwrap_or_default();
    if alg != "EdDSA" {
        return Err(AppError::invalid_param(
            "keys/upload device_signature.alg must be EdDSA",
        ));
    }
    let kid = device_signature.kid.as_str();
    if !device_signature_kid_points_to_device_key(kid, actor, device_public_key) {
        return Err(AppError::invalid_param(
            "keys/upload device_signature.kid does not point to the authorized device key",
        ));
    }
    let signing_input = keys_upload_signing_input(device_id, one_time_keys, fallback_keys)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(device_signature.sig.as_bytes())
        .map_err(|_| AppError::invalid_param("keys/upload signature is not base64url"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| AppError::invalid_param("keys/upload signature must be 64 bytes"))?;
    let verifying_key =
        crate::routing::identity::cross_signing::decode_ed25519_key(device_public_key, "multibase")
            .map_err(|error| {
                AppError::invalid_param(format!("device signing key is invalid: {error}"))
            })?;
    use ed25519_dalek::Verifier as _;
    verifying_key
        .verify(&signing_input, &signature)
        .map_err(|_| AppError::invalid_param("keys/upload signature verification failed"))
}

#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.command.claim"))]
async fn keys_claim(
    aa: AuthArgs,
    body: JsonBody<KeysClaimRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysClaimOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _ = aa.authenticated_session(state, req).await?;

    let body = body.into_inner();
    let mut claimed = BTreeMap::new();
    for (actor, devices) in body.one_time_keys {
        let mut device_map = BTreeMap::new();
        for (device_id, algorithm) in devices {
            let facet =
                crate::routing::identity::cross_signing::resolve_device_signing_directory_facet(
                    state,
                    actor.as_str(),
                    device_id.as_str(),
                )
                .await;
            if !matches!(facet.status, DeviceStatus::Active) {
                continue;
            }
            if let Ok(Some(key)) = state
                .key_material_application()
                .claim_one_time_key(actor.as_str(), device_id.as_str())
                .await
            {
                let key = serde_json::from_value(key).map_err(|error| {
                    AppError::internal(format!("stored one-time key is invalid: {error}"))
                })?;
                device_map.insert(device_id, BTreeMap::from([(algorithm, key)]));
            }
        }
        claimed.insert(actor, device_map);
    }
    json_ok(KeysClaimOutcome {
        one_time_keys: claimed,
        failures: Vec::new(),
    })
}

/// Server-to-server bearer gate for the device signing-key directory read.
///
/// Reuses the deployment's `SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER`: the Auth
/// Server (coauth) already holds this static bearer for the same Principal
/// Server (it registers embedded `did:webvh` records with it), so the directory
/// read it issues while verifying a device holder proof rides the same trust
/// edge without minting a second credential. Compared in constant-ish form via
/// SHA-256 digests of both sides.
fn require_device_directory_bearer(state: &AppState, req: &Request) -> Result<(), AppError> {
    let Some(expected) = state
        .config()
        .embedded_webvh_registration_bearer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(AppError::new(
            soland_http::error::ErrorCode::TemporarilyUnavailable,
            "device signing-key directory read requires SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER",
        )
        .with_status(StatusCode::SERVICE_UNAVAILABLE));
    };
    let Some(provided) = bearer_token(req)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(AppError::unauthenticated(
            "device signing-key directory read requires Authorization: Bearer <token>",
        ));
    };
    if sha256_hex(provided.as_bytes()) != sha256_hex(expected.as_bytes()) {
        return Err(AppError::unauthenticated(
            "invalid device signing-key directory bearer",
        ));
    }
    Ok(())
}

#[handler]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.gate.account.device_signing_keys.query")
)]
async fn device_signing_keys_query(
    body: JsonBody<DeviceSigningKeyDirectoryQueryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeviceSigningKeyDirectoryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_device_directory_bearer(state, req)?;

    let body = body.into_inner();
    let principal_id = body.principal_id;

    // Resolve the target device-id set. An explicit, non-empty `device_ids`
    // restricts the lookup; otherwise enumerate the principal's directory
    // (revoked devices are dropped below by the facet predicate either way).
    let device_ids: Vec<String> = if body.device_ids.is_empty() {
        state
            .identity_application()
            .devices_for_actor(principal_id.as_str())
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .into_iter()
            .map(|record| record.device_id)
            .collect()
    } else {
        body.device_ids
            .into_iter()
            .map(|device_id| device_id.as_str().to_owned())
            .collect()
    };

    let mut devices = Vec::new();
    for device_id in device_ids {
        // Single source of truth: the same verified + non-revoked predicate the
        // `keys/query` directory facet applies (device-lifecycle.md §8.2). A
        // revoked / unverified device yields no `signing_key_did`, so it never
        // surfaces here.
        let facet =
            crate::routing::identity::cross_signing::resolve_device_signing_directory_facet(
                state,
                principal_id.as_str(),
                &device_id,
            )
            .await;
        if !matches!(facet.status, DeviceStatus::Active) {
            continue;
        }
        let Some(device_signing_key) = facet.signing_key_did else {
            continue;
        };
        let Ok(typed_device_id) = arkret_identifiers::DeviceId::new(device_id.clone()) else {
            continue;
        };
        devices.push(AuthorizedDeviceSigningKey {
            device_id: typed_device_id,
            device_signing_key,
            device_status: DeviceStatus::Active,
            device_authorize_event_id: facet.device_authorize_event_id,
        });
    }

    json_ok(DeviceSigningKeyDirectoryOutcome {
        principal_id,
        devices,
    })
}
