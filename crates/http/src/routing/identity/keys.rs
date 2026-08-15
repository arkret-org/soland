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
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};
use soland_services::identity::{DeviceIdentity, FindDeviceQuery, SaveDeviceCommand};

use super::{bearer_token, is_device_revoked, now, sha256_hex};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{
    AuthorizedDeviceSigningKey, DeviceSigningKeyDirectoryOutcome,
    DeviceSigningKeyDirectoryQueryRequestBody, DeviceStatus, KeysClaimOutcome,
    KeysClaimRequestBody, KeysQueryOutcome, KeysQueryRequestBody, KeysUploadOutcome,
    KeysUploadRequestBody, KeysUploadUnsignedRequest, QueryDeviceRecord,
};

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

#[salvo::oapi::endpoint(operation_id = "ak.self.keys.upload.create", tags("identity"))]
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
    let unsigned = body.unsigned();
    let device_id = body.device_id.as_str().to_owned();
    if device_id != session.device_id {
        return Err(AppError::capability_denied(
            "session device does not match upload device",
        ));
    }
    let current_device = state
        .identities()
        .find_device(FindDeviceQuery {
            actor_id: session.actor.clone(),
            device_id: device_id.clone(),
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let current_facet =
        crate::routing::identity::device_signing::resolve_device_signing_directory_facet(
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
        current_device.as_ref(),
        &unsigned,
        &body.device_signature,
    )?;

    let one_time_key_count = body.one_time_keys.len() as u64;
    let mut one_time_key_alg_counts = BTreeMap::new();
    for key_id in body.one_time_keys.keys() {
        let algorithm = key_id.as_str().split(':').next().unwrap_or(key_id.as_str());
        *one_time_key_alg_counts
            .entry(
                arkret_wire::NonEmptyString::new(algorithm.to_owned()).map_err(|error| {
                    AppError::param_invalid(format!("one-time key algorithm is invalid: {error}"))
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
        .key_material()
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
        .identities()
        .save_device(SaveDeviceCommand {
            actor_id: session.actor.clone(),
            device_id: device_id.clone(),
            display_name: device.display_name.clone(),
            device,
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    if let Err(error) = state
        .key_material()
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

/// Freshness window of a device projection attestation.
///
/// Short by design: `device-lifecycle.md` §8.3 lets a consumer cache the
/// verified projection under `(principal_id, principal_server_id, device_id,
/// authorized_generation_ref, attested_at)`, and this bound is what stops that
/// cache from outliving a device revocation the caller has not re-fetched.
const DEVICE_PROJECTION_ATTESTATION_TTL_SECONDS: i64 = 300;

/// Build one complete, origin-Principal-Server-attested `keys/query` row.
///
/// Returns `None` when the device is not currently usable. §8.2 makes that the
/// only two outcomes: the surface returns a fully attested row, or it returns
/// nothing for that `(principal_id, device_id)` — which is also the
/// anti-enumeration shape, since an omission is indistinguishable from "no
/// relationship" and from "no such device".
async fn attested_device_record(
    state: &AppState,
    principal_id: &arkret_wire::DidCoreId,
    device_id: &arkret_wire::DeviceId,
    facet: crate::routing::identity::device_signing::DeviceSigningDirectoryFacet,
    algorithms: arkret_models_crypto::AlgorithmKeyRecords,
) -> Result<Option<QueryDeviceRecord>, AppError> {
    if !matches!(facet.status, DeviceStatus::Active) {
        return Ok(None);
    }
    let (
        Some(signing_key_did),
        Some(hpke_key),
        Some(trust_algorithms),
        Some(device_authorize_event_id),
        Some(authorized_generation_ref),
    ) = (
        facet.signing_key_did,
        facet.hpke_key,
        facet.trust_algorithms,
        facet.device_authorize_event_id,
        facet.authorized_generation_ref,
    )
    else {
        return Ok(None);
    };
    let device_signing_key = arkret_wire::DidKey::new(signing_key_did).map_err(|error| {
        AppError::internal(format!("stored device signing key is invalid: {error}"))
    })?;
    let hpke_key = arkret_wire::NonEmptyString::new(hpke_key)
        .map_err(|error| AppError::internal(format!("stored HPKE key is invalid: {error}")))?;
    let trust_algorithms = trust_algorithms
        .into_iter()
        .map(arkret_wire::NonEmptyString::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            AppError::internal(format!("stored trust algorithm is invalid: {error}"))
        })?;

    let attested_at = now();
    let (_, verification_method) = state
        .current_service_receipt_binding()
        .await
        .map_err(AppError::internal)?;
    let attestation = arkret_signatures::device_projection::sign_device_projection_attestation(
        arkret_models_crypto::DeviceProjectionAttestationCore {
            principal_id: principal_id.clone(),
            principal_server_id: arkret_wire::DidCoreId::new(state.service_id().clone()).map_err(
                |error| AppError::internal(format!("service id is not a did_core_id: {error}")),
            )?,
            device_id: device_id.clone(),
            device_signing_key: device_signing_key.clone(),
            hpke_key: hpke_key.clone(),
            device_authorize_event_id: device_authorize_event_id.clone(),
            authorized_generation_ref,
            device_status: DeviceStatus::Active,
            attested_at,
            expires_at: attested_at
                + chrono::Duration::seconds(DEVICE_PROJECTION_ATTESTATION_TTL_SECONDS),
        },
        verification_method,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| {
        AppError::internal(format!("device projection attestation failed: {error}"))
    })?;

    let record = QueryDeviceRecord {
        algorithms,
        device_signing_key,
        hpke_key,
        trust_algorithms,
        device_status: DeviceStatus::Active,
        device_authorize_event_id,
        authorized_generation_ref,
        device_projection_attestation: attestation,
    };
    record
        .validate_attestation_binding(principal_id, device_id)
        .map_err(|error| {
            AppError::internal(format!(
                "device projection attestation does not bind its own row: {error}"
            ))
        })?;
    Ok(Some(record))
}

#[salvo::oapi::endpoint(operation_id = "ak.self.keys.read.lookup", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.read.lookup"))]
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
    let mut device_generations = BTreeMap::new();
    for (actor_core, devices) in body.device_keys {
        if !keys_query_actor_visible_to_requester(state, &session.actor, actor_core.as_str()) {
            continue;
        }
        if let Some(generation) =
            crate::routing::identity::device_generation::current_device_generation(
                state,
                actor_core.as_str(),
            )
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
        {
            device_generations.insert(
                actor_core.clone(),
                arkret_models_crypto::keys::DeviceGenerationState {
                    current_device_generation_ref: generation.current_ref,
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
                .identities()
                .find_device(FindDeviceQuery {
                    actor_id: actor_core.as_str().to_owned(),
                    device_id: device_id.as_str().to_owned(),
                })
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            if device_record.is_none() {
                continue;
            }
            // Carry the opaque uploaded prekey blob under `algorithms`. The demo
            // upload stores one payload object per device, so it is surfaced as a
            // single `algorithms` map (key→value) rather than per-algorithm
            // key_records; the directory facet below is the real signing-key data.
            let algorithms = match state
                .key_material()
                .bundle(actor_core.as_str(), device_id.as_str())
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
                crate::routing::identity::device_signing::resolve_device_signing_directory_facet(
                    state,
                    actor_core.as_str(),
                    device_id.as_str(),
                )
                .await;
            // `device-lifecycle.md` §8.2: a row is complete and attested or it
            // is not returned. A revoked, unverified, fenced or conflicted
            // device is omitted entirely rather than degraded into a partial
            // row, so its prekey bundle is never surfaced, no signing key
            // leaks, and a caller can never mistake an incomplete row for a
            // usable one.
            let Some(record) =
                attested_device_record(state, &actor_core, &device_id, facet, algorithms).await?
            else {
                continue;
            };
            actor_keys.insert(device_id, record);
        }
        result.insert(actor_core, actor_keys);
    }
    json_ok(KeysQueryOutcome {
        device_keys: result,
        failures: Vec::new(),
        device_generations,
    })
}

fn keys_query_actor_visible_to_requester(state: &AppState, requester: &str, actor: &str) -> bool {
    if requester == actor {
        return true;
    }
    let Ok(requester_actor_id) = arkret_identifiers::DidCoreId::new(requester.to_owned()) else {
        return false;
    };
    let Ok(actor_did) = arkret_identifiers::DidCoreId::new(actor.to_owned()) else {
        return false;
    };
    let realms = state.realm_directory().snapshot();
    let projection = state.projections().snapshot();
    realms.entries_iter().any(|(realm_id, entry)| {
        if !entry.members.contains(&requester_actor_id) {
            return false;
        }
        if entry.members.contains(&actor_did) {
            return true;
        }
        projection
            .member(realm_id.as_str(), actor)
            .is_some_and(|membership| matches!(membership.state.as_str(), "join" | "leave" | "ban"))
    })
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
    let expected_principal_id_key = device_public_key
        .strip_prefix("did:key:")
        .map_or_else(|| format!("did:key:{device_public_key}"), str::to_owned);
    kid == expected_principal_id_key
        || kid
            .strip_prefix(&expected_principal_id_key)
            .is_some_and(|rest| rest.starts_with('#') || rest.starts_with('?'))
        || verification_method_controller(kid) == actor
        || arkret_wire::DidFullId::new(verification_method_controller(kid).to_owned())
            .and_then(|controller| arkret_wire::project_full_id_to_core_id(&controller))
            .is_ok_and(|controller| controller.as_str() == actor)
}

fn verify_keys_upload_device_signature(
    actor: &str,
    current_device: Option<&DeviceIdentity>,
    unsigned: &KeysUploadUnsignedRequest,
    device_signature: &arkret_models_crypto::artifacts_keys::KeyOperationSignature,
) -> Result<(), AppError> {
    let record = current_device.ok_or_else(|| {
        AppError::param_invalid("keys/upload requires an authorized device_public_key")
    })?;
    if record.verification_state != "verified" || record.revoked_at.is_some() {
        return Err(AppError::param_invalid(
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
            AppError::param_invalid("keys/upload requires authoritative device_public_key")
        })?;
    let signature_algorithm = device_signature
        .signature_algorithm
        .as_ref()
        .map(arkret_wire::NonEmptyString::as_str)
        .unwrap_or_default();
    if signature_algorithm != "Ed25519" {
        return Err(AppError::param_invalid(
            "keys/upload device_signature.signature_algorithm must be Ed25519",
        ));
    }
    let kid = device_signature.kid.as_str();
    if !device_signature_kid_points_to_device_key(kid, actor, device_public_key) {
        return Err(AppError::param_invalid(
            "keys/upload device_signature.kid does not point to the authorized device key",
        ));
    }
    let signing_input = arkret_models_crypto::keys_upload_signing_input(unsigned)
        .map_err(|error| AppError::param_invalid(format!("keys/upload canonicalize: {error}")))?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(device_signature.sig.as_bytes())
        .map_err(|_| AppError::param_invalid("keys/upload signature is not base64url"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| AppError::param_invalid("keys/upload signature must be 64 bytes"))?;
    let verifying_key = crate::routing::identity::device_signing::decode_ed25519_key(
        device_public_key,
        "multibase",
    )
    .map_err(|error| AppError::param_invalid(format!("device signing key is invalid: {error}")))?;
    use ed25519_dalek::Verifier as _;
    verifying_key
        .verify(&signing_input, &signature)
        .map_err(|_| AppError::param_invalid("keys/upload signature verification failed"))
}

#[salvo::oapi::endpoint(operation_id = "ak.self.keys.command.claim", tags("identity"))]
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
        let actor_core = arkret_wire::project_full_id_to_core_id(&actor).map_err(|error| {
            AppError::param_invalid(format!("claim actor cannot project: {error}"))
        })?;
        let mut device_map = BTreeMap::new();
        for (device_id, algorithm) in devices {
            let facet =
                crate::routing::identity::device_signing::resolve_device_signing_directory_facet(
                    state,
                    actor_core.as_str(),
                    device_id.as_str(),
                )
                .await;
            if !matches!(facet.status, DeviceStatus::Active) {
                continue;
            }
            if let Ok(Some(key)) = state
                .key_material()
                .claim_one_time_key(actor_core.as_str(), device_id.as_str())
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

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.soland.gate.account.device_signing_keys.query",
    tags("identity")
)]
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
            .identities()
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
            crate::routing::identity::device_signing::resolve_device_signing_directory_facet(
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

#[cfg(test)]
mod tests {
    use super::device_signature_kid_points_to_device_key;

    #[test]
    fn device_signature_kid_projects_full_controller_to_core_actor() {
        assert!(device_signature_kid_points_to_device_key(
            "did:web:alice.example#ak:device:primary",
            "ak:did_core:web:alice.example",
            "z6MkAuthorizedDeviceKey",
        ));
        assert!(!device_signature_kid_points_to_device_key(
            "did:web:mallory.example#ak:device:primary",
            "ak:did_core:web:alice.example",
            "z6MkAuthorizedDeviceKey",
        ));
    }
}
