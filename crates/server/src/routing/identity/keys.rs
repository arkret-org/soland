//! E2EE key surfaces.
//!
//! Surfaces:
//! - `POST /_cokret/self/keys/upload` - upload one-time / fallback prekeys with the current device
//!   signature.
//! - `POST /_cokret/self/keys/query` - fetch device key bundles for a peer set.
//! - `POST /_cokret/self/keys/claim` - claim one-time keys, draining the per-device pool.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::Signature;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{bearer_token, is_device_revoked, now, sha256_hex};
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::routing::system::extract::AuthArgs;
use crate::state::{AppState, DeviceInventoryRecord};
use crate::wire::{
    AuthorizedDeviceSigningKey, DeviceSigningKeyDirectoryOutcome,
    DeviceSigningKeyDirectoryQueryRequestBody, DeviceStatus, KeysClaimOutcome,
    KeysClaimRequestBody, KeysQueryOutcome, KeysQueryRequestBody, KeysUploadOutcome,
    KeysUploadRequestBody, QueryDeviceRecord,
};

const KEYS_UPLOAD_SIGNATURE_PREFIX: &[u8] = b"ck-keys-upload-v1\n";

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("keys/upload").post(keys_upload))
        .push(Router::with_path("keys/query").post(keys_query))
        .push(Router::with_path("keys/claim").post(keys_claim))
}

/// Product-surface (`/_soland/gate/account/...`) router carrying the
/// server-to-server device signing-key directory read used by the Auth Server
/// (coauth) to verify device holder proofs. Mounted under `_soland`, not the
/// `/_cokret` protocol root: it is a deployment-local integration read, not a
/// spec operation.
pub(super) fn product_router() -> Router {
    Router::with_path("gate/account/device-signing-keys/query").post(device_signing_keys_query)
}

#[endpoint(
    operation_id = "ck.self.keys.upload.create",
    tags("keys"),
    summary = "Upload device + one-time keys for the current session device"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.keys.upload.create"))]
async fn keys_upload(
    aa: AuthArgs,
    body: JsonBody<KeysUploadRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysUploadOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
        .persistence
        .devices()
        .get(&session.actor, &device_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
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
        let algorithm = key_id.split(':').next().unwrap_or(key_id.as_str());
        *one_time_key_alg_counts
            .entry(algorithm.to_owned())
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
        .persistence
        .device_keys()
        .put(
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
    let device = DeviceInventoryRecord {
        actor: session.actor.clone(),
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
        .persistence
        .devices()
        .put(&device)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    if let Err(error) = state
        .persistence
        .one_time_keys()
        .put(
            session.actor,
            device_id,
            one_time_keys.into_values().collect(),
        )
        .await
    {
        tracing::error!(%error, "failed to persist one-time keys");
    }

    one_time_key_alg_counts.insert("total".to_owned(), one_time_key_count);
    json_ok(KeysUploadOutcome {
        one_time_key_counts: one_time_key_alg_counts,
        fallback_keys,
    })
}

#[endpoint(
    operation_id = "ck.self.keys.query.lookup",
    tags("keys"),
    summary = "Fetch device key bundles for a peer set"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.keys.query.lookup"))]
async fn keys_query(
    aa: AuthArgs,
    body: JsonBody<KeysQueryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysQueryOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;

    let body = body.into_inner();
    let store = state.persistence.device_keys();
    let mut result = BTreeMap::new();
    let mut cross_signing = BTreeMap::new();
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
        let mut actor_keys = BTreeMap::new();
        for device_id in devices {
            let device_record = state
                .persistence
                .devices()
                .get(actor.as_str(), device_id.as_str())
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
            let mut algorithms = match store.get(actor.as_str(), device_id.as_str()).await {
                Ok(Some(Value::Object(map))) => map.into_iter().collect(),
                Ok(Some(other)) => BTreeMap::from([("key".to_owned(), other)]),
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
                    device_signing_key: facet.signing_key_did,
                    hpke_key: facet.hpke_key,
                    trust_algorithms: facet.trust_algorithms,
                    device_status: Some(facet.status),
                    cross_signing_binding: facet.cross_signing_binding,
                    enrollment_authority_binding: facet.enrollment_authority_binding,
                    device_authorize_event_id: facet.device_authorize_event_id,
                },
            );
        }
        result.insert(actor, actor_keys);
    }
    json_ok(KeysQueryOutcome {
        device_keys: result,
        failures: Vec::new(),
        cross_signing,
    })
}

fn keys_query_actor_visible_to_requester(state: &AppState, requester: &str, actor: &str) -> bool {
    if requester == actor {
        return true;
    }
    let Ok(requester_did) = cokret_sdk::Did::new(requester.to_owned()) else {
        return false;
    };
    let Ok(actor_did) = cokret_sdk::Did::new(actor.to_owned()) else {
        return false;
    };
    state
        .realms
        .lock()
        .expect("realms lock")
        .entries_iter()
        .any(|(_, entry)| {
            entry.members.contains(&requester_did) && entry.members.contains(&actor_did)
        })
}

fn keys_upload_signing_input(
    device_id: &str,
    one_time_keys: &BTreeMap<String, Value>,
    fallback_keys: &BTreeMap<String, Value>,
) -> Result<Vec<u8>, AppError> {
    let body = json!({
        "device_id": device_id,
        "one_time_keys": one_time_keys,
        "fallback_keys": fallback_keys,
    });
    let canonical = cokret_sdk::canonical::canonical_json_bytes(&body)
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

fn device_signature_kid_points_to_device_key(
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
    current_device: Option<&DeviceInventoryRecord>,
    one_time_keys: &BTreeMap<String, Value>,
    fallback_keys: &BTreeMap<String, Value>,
    device_signature: &Value,
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
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if alg != "EdDSA" {
        return Err(AppError::invalid_param(
            "keys/upload device_signature.alg must be EdDSA",
        ));
    }
    let kid = device_signature
        .get("kid")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::invalid_param("keys/upload device_signature.kid is required"))?;
    if !device_signature_kid_points_to_device_key(kid, actor, device_public_key) {
        return Err(AppError::invalid_param(
            "keys/upload device_signature.kid does not point to the authorized device key",
        ));
    }
    let jws = device_signature
        .get("jws")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::invalid_param("keys/upload device_signature.jws is required"))?;
    let signing_input = keys_upload_signing_input(device_id, one_time_keys, fallback_keys)?;
    verify_detached_jws_ed25519_with_device_key(device_public_key, &signing_input, jws)
}

fn verify_detached_jws_ed25519_with_device_key(
    device_public_key: &str,
    canonical_bytes: &[u8],
    jws: &str,
) -> Result<(), AppError> {
    let parts = jws.split('.').collect::<Vec<_>>();
    if parts.len() != 3 || !parts[1].is_empty() {
        return Err(AppError::invalid_param(
            "keys/upload device_signature.jws must be detached header..signature",
        ));
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0].as_bytes())
        .map_err(|_| AppError::invalid_param("keys/upload JWS header is not base64url"))?;
    let header: Value = cokret_sdk::canonical::from_canonical_json_slice(&header_bytes)
        .map_err(|_| AppError::invalid_param("keys/upload JWS header is not canonical JSON"))?;
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        return Err(AppError::invalid_param(
            "keys/upload JWS protected alg must be EdDSA",
        ));
    }
    if header.get("crit").is_some() {
        return Err(AppError::invalid_param(
            "keys/upload JWS protected header declares unsupported crit",
        ));
    }
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2].as_bytes())
        .map_err(|_| AppError::invalid_param("keys/upload JWS signature is not base64url"))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| AppError::invalid_param("keys/upload Ed25519 signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_array);
    let verifying_key =
        crate::routing::identity::cross_signing::decode_ed25519_key(device_public_key, "multibase")
            .map_err(|error| {
                AppError::invalid_param(format!(
                    "keys/upload device_public_key is not Ed25519 multibase: {error}"
                ))
            })?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(canonical_bytes);
    let signing_input = format!("{}.{}", parts[0], payload_b64);
    verifying_key
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|_| AppError::invalid_param("keys/upload device_signature verification failed"))
}

#[endpoint(
    operation_id = "ck.self.keys.command.claim",
    tags("keys"),
    summary = "Claim one-time keys, draining the per-device pool"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.keys.command.claim"))]
async fn keys_claim(
    aa: AuthArgs,
    body: JsonBody<KeysClaimRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysClaimOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _ = aa.authenticated_session(state, req).await?;

    let body = body.into_inner();
    let store = state.persistence.one_time_keys();
    let mut claimed = BTreeMap::new();
    for (actor, devices) in body.one_time_keys {
        let mut device_map = BTreeMap::new();
        for (device_id, _algorithm) in devices {
            if let Ok(Some(key)) = store.claim(actor.as_str(), device_id.as_str()).await {
                device_map.insert(device_id, key);
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
        .config
        .embedded_webvh_registration_bearer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(AppError::new(
            crate::error::ErrorCode::TemporarilyUnavailable,
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

#[endpoint(
    operation_id = "org.cokret.soland.gate.account.device_signing_keys.query",
    tags("keys"),
    summary = "Look up authorized, non-revoked device signing keys for a principal (server-to-server)"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.cokret.soland.gate.account.device_signing_keys.query")
)]
async fn device_signing_keys_query(
    body: JsonBody<DeviceSigningKeyDirectoryQueryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeviceSigningKeyDirectoryOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    require_device_directory_bearer(state, req)?;

    let body = body.into_inner();
    let principal_id = body.principal_id;

    // Resolve the target device-id set. An explicit, non-empty `device_ids`
    // restricts the lookup; otherwise enumerate the principal's directory
    // (revoked devices are dropped below by the facet predicate either way).
    let device_ids: Vec<String> = if body.device_ids.is_empty() {
        state
            .persistence
            .devices()
            .list_for_actor(principal_id.as_str())
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
        let Ok(typed_device_id) = cokret_sdk::DeviceId::new(device_id.clone()) else {
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
