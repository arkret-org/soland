//! Push notification surfaces (register / unregister / notify).
//!
//! Surfaces:
//! - `POST /_arkret/edge/push/register-device` — register a device token + push gateway
//! - `POST /_arkret/edge/push/unregister-device` — remove an authenticated actor's device token
//! - `POST /_arkret/edge/push/notify` — validate the privacy-preserving target and gateway contract
//!   before fan-out.
//!
//! Device registration authenticates with an ordinary bearer session; there is
//! no header-carried alternative.
//! Spec rule: no DID in push payload / TURN username.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};
use sha2::Sha256;
use soland_http::error::AppError;
use soland_http::result::{JsonResult, json_ok};
use soland_services::delivery::PushContractDrift as DriftResult;
use subtle::ConstantTimeEq;

use super::audit::append_audit_log;
use super::push_outbound::{derive_push_gateway_service_base_url, join_push_gateway_url};
use super::{authenticated_session, now, sha256_hex};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{
    PushNotifyOutcome, PushNotifyRequestBody, PushRegisterDeviceRequestBody,
    PushUnregisterDeviceRequestBody,
};

/// C33.1 (T0-3a): freshness budget for the persisted gateway-contract
/// snapshot before `push_notify` fails closed. Picked to be lenient enough
/// to absorb a routine refresh cadence but tight enough to surface a stuck
/// fetch worker before fan-out leaks past a stale contract. v1 unreleased,
/// no operator knob yet — bump here when the refresh worker lands.
const PUSH_GATEWAY_CONTRACT_MAX_AGE_HOURS: i64 = 24;
pub(crate) const PUSH_TARGET_SALT_ROTATION_SECONDS: i64 = 30 * 24 * 60 * 60;
const PUSH_TARGET_RETAIN_SECONDS: i64 = 24 * 60 * 60;

pub(crate) fn push_target_privacy_derivation_claim(
    now: chrono::DateTime<chrono::Utc>,
) -> arkret_models_discovery::service_description::PrivacyDerivation {
    arkret_models_discovery::service_description::PrivacyDerivation {
        push_target_id: Some(arkret_models_discovery::service_description::PushTargetPrivacyDerivation {
            derivation_profile: arkret_models_discovery::service_description::PushTargetDerivationProfile::HmacSha256V1,
            secret_scope: arkret_models_discovery::service_description::PushTargetSecretScope::PerService,
            salt_epoch_id: push_target_salt_epoch_id_at(now),
            salt_rotation_seconds: PUSH_TARGET_SALT_ROTATION_SECONDS as u64,
            input_binding: Some(vec![
                arkret_models_discovery::service_description::PushTargetInputBinding::RecipientDidCoreId,
                arkret_models_discovery::service_description::PushTargetInputBinding::DidCoreId,
                arkret_models_discovery::service_description::PushTargetInputBinding::DeviceId,
                arkret_models_discovery::service_description::PushTargetInputBinding::PushRouteId,
                arkret_models_discovery::service_description::PushTargetInputBinding::SaltEpochId,
            ]),
        }),
    }
}

fn push_target_salt_epoch_id_at(now: chrono::DateTime<chrono::Utc>) -> String {
    let epoch = now
        .timestamp()
        .div_euclid(PUSH_TARGET_SALT_ROTATION_SECONDS);
    format!("ak.push.salt_epoch.{epoch}")
}

const PUSH_TARGET_ID_PREFIX: &str = "ak:pseudonym:push:";

/// The keyed pairwise tag both the push target pseudonym and the gateway-local
/// registration handle are spelled from.
fn derive_push_target_tag(
    root_key: &[u8; 32],
    recipient_service_id: &str,
    principal_id: &str,
    device_id: &str,
    push_route_id: &str,
    salt_epoch_id: &str,
) -> Result<String, AppError> {
    let input = json!({
        "recipient_service_id": recipient_service_id,
        "principal_id": principal_id,
        "device_id": device_id,
        "push_route_id": push_route_id,
        "salt_epoch_id": salt_epoch_id,
    });
    let canonical = arkret_canonical::canonical_json_bytes(&input)
        .map_err(|error| AppError::internal(format!("push target canonicalize: {error}")))?;
    let epoch_key = hmac_sha256(root_key, salt_epoch_id.as_bytes());
    let tag = hmac_sha256(&epoch_key, &canonical);
    Ok(URL_SAFE_NO_PAD.encode(tag))
}

/// The registration path composes this inline because it also needs the bare
/// tag for `push_registration_id`. Only the derivation tests want the wire
/// spelling on its own, so this carries their gate rather than an allow.
#[cfg(test)]
fn derive_push_target_id(
    root_key: &[u8; 32],
    recipient_service_id: &str,
    principal_id: &str,
    device_id: &str,
    push_route_id: &str,
    salt_epoch_id: &str,
) -> Result<String, AppError> {
    let tag = derive_push_target_tag(
        root_key,
        recipient_service_id,
        principal_id,
        device_id,
        push_route_id,
        salt_epoch_id,
    )?;
    Ok(format!("{PUSH_TARGET_ID_PREFIX}{tag}"))
}

/// Gateway-local registration handle for one accepted push registration.
///
/// `push-operations.schema.json#/$defs/registration_id` is an
/// `opaque_correlation` carrier, so it MUST NOT borrow the `ak:` typed-ID
/// lexical space the push target pseudonym owns. It is spelled from the same
/// pairwise tag, so re-registering an unchanged route stays idempotent without
/// minting a second correlation key.
fn push_registration_id(push_target_tag: &str) -> Result<arkret_wire::OpaqueLocalId, AppError> {
    arkret_wire::OpaqueLocalId::new(format!("push_registration:{push_target_tag}"))
        .map_err(|error| AppError::internal(format!("push registration id is invalid: {error}")))
}
#[salvo::oapi::endpoint(operation_id = "ak.edge.push.command.register_device", tags("interop"))]
#[tracing::instrument(skip_all, fields(op = "ak.edge.push.command.register_device"))]
pub(super) async fn push_register(
    body: JsonBody<PushRegisterDeviceRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<arkret_models_integration::models_push::PushRegisterDeviceOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let auth_result = authenticated_session(state, req);
    let body = body.into_inner();
    let session = match auth_result.await {
        Ok(session) => session,
        Err((status, code, message)) => {
            return Err(AppError::new(canonical_error_code(code), message).with_status(status));
        }
    };
    if body.device_id.as_str().trim().is_empty() {
        return Err(AppError::param_invalid("invalid device_id"));
    }
    let principal_id = session.actor.clone();
    let device_id = body.device_id.as_str().to_owned();
    let platform = body.platform.clone();
    let app_id = body.app_id.clone();
    let push_gateway = body.push_gateway.clone();
    let push_key = body.push_key.clone();
    let recipient_service_id = body
        .recipient_service_id
        .as_ref()
        .map(|did| did.as_str())
        .unwrap_or(state.service_id().as_str());
    if recipient_service_id != state.service_id() {
        return Err(AppError::param_invalid(
            "recipient_service_id must match this service",
        ));
    }
    let push_route_id = push_route_id_for_registration(&body);
    let salt_epoch_id = push_target_salt_epoch_id_at(now());
    let push_target_tag = derive_push_target_tag(
        state.deliveries().push_target_hmac_key(),
        state.service_id(),
        &principal_id,
        &device_id,
        &push_route_id,
        &salt_epoch_id,
    )?;
    let push_target_id = format!("{PUSH_TARGET_ID_PREFIX}{push_target_tag}");
    let registration_id = push_registration_id(&push_target_tag)?;
    let previous_registrations = state
        .deliveries()
        .push_devices()
        .await
        .unwrap_or_else(|error| {
            tracing::error!(%error, "failed to read prior push device registrations");
            Vec::new()
        });
    let retained_push_targets = retained_push_targets_for_route(
        &previous_registrations,
        &principal_id,
        &device_id,
        &push_route_id,
        &push_target_id,
        now() + chrono::Duration::seconds(PUSH_TARGET_RETAIN_SECONDS),
    );
    state
        .deliveries()
        .unregister_push_device(&principal_id, &device_id, None, app_id.as_deref())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if let Err(error) = state
        .deliveries()
        .register_push_device(json!({
            "registration_id": registration_id,
            "actor": session.actor,
            "principal_id": principal_id,
            "device_id": device_id,
            "platform": platform,
            "app_id": app_id,
            "push_gateway": push_gateway,
            "push_key": push_key,
            "recipient_service_id": state.service_id().as_str(),
            "push_route_id": push_route_id,
            "push_target_id": push_target_id,
            "salt_epoch_id": salt_epoch_id,
            "salt_rotation_seconds": PUSH_TARGET_SALT_ROTATION_SECONDS,
            "retained_push_targets": retained_push_targets,
            "auth_mode": "bearer",
        }))
        .await
    {
        tracing::error!(%error, "failed to persist push device registration");
    }
    json_ok(
        arkret_models_integration::models_push::PushRegisterDeviceOutcome {
            ok: true,
            registration_id: Some(registration_id),
            expires_at: None,
        },
    )
}

/// Map the `(status, code, message)` triplet produced by
/// `authenticated_session` to a canonical `ErrorCode`. The lookup is fast and
/// lossless because the call site only emits a small closed set.
fn canonical_error_code(wire: &str) -> soland_http::error::ErrorCode {
    use soland_http::error::ErrorCode;
    match wire {
        "missing_auth" | "unauthenticated" => ErrorCode::Unauthenticated,
        "param_invalid" | "param_missing" => ErrorCode::ParamInvalid,
        "session_expired" => ErrorCode::CursorExpired,
        _ => ErrorCode::InternalError,
    }
}

fn push_route_id_for_registration(body: &PushRegisterDeviceRequestBody) -> String {
    body.app_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            body.platform
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| format!("platform:{value}"))
        })
        .unwrap_or_else(|| {
            let route_digest =
                sha256_hex(format!("{}|{}", body.push_gateway, body.push_key).as_bytes());
            format!("gateway:{route_digest}")
        })
}

fn retained_push_targets_for_route(
    registrations: &[Value],
    principal_id: &str,
    device_id: &str,
    push_route_id: &str,
    new_push_target_id: &str,
    retained_until: chrono::DateTime<chrono::Utc>,
) -> Vec<Value> {
    registrations
        .iter()
        .filter(|registration| {
            registration.get("actor").and_then(Value::as_str) == Some(principal_id)
                && registration.get("device_id").and_then(Value::as_str) == Some(device_id)
                && registration.get("push_route_id").and_then(Value::as_str) == Some(push_route_id)
        })
        .filter_map(|registration| {
            let target = registration.get("push_target_id").and_then(Value::as_str)?;
            if target == new_push_target_id {
                return None;
            }
            Some(json!({
                "push_target_id": target,
                "salt_epoch_id": registration
                    .get("salt_epoch_id")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
                "retained_until": retained_until,
            }))
        })
        .collect()
}

fn push_registration_accepts_target(
    registration: &Value,
    push_target_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    if registration
        .get("push_target_id")
        .and_then(Value::as_str)
        .is_some_and(|registered| constant_time_str_eq(registered, push_target_id))
    {
        return true;
    }
    registration
        .get("retained_push_targets")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|entry| {
            let target_matches = entry
                .get("push_target_id")
                .and_then(Value::as_str)
                .is_some_and(|registered| constant_time_str_eq(registered, push_target_id));
            if !target_matches {
                return false;
            }
            entry
                .get("retained_until")
                .and_then(Value::as_str)
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .map(|retained_until| retained_until.with_timezone(&chrono::Utc) >= now)
                .unwrap_or(false)
        })
}

fn constant_time_str_eq(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[salvo::oapi::endpoint(
    operation_id = "ak.edge.push.command.unregister_device",
    tags("interop")
)]
#[tracing::instrument(skip_all, fields(op = "ak.edge.push.command.unregister_device"))]
pub(super) async fn push_unregister(
    aa: AuthArgs,
    body: JsonBody<PushUnregisterDeviceRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<arkret_models_integration::models_push::PushUnregisterDeviceOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if body.device_id.as_str().trim().is_empty() {
        return Err(AppError::param_invalid("invalid device_id"));
    }
    let removed = state
        .deliveries()
        .unregister_push_device(
            &session.actor,
            body.device_id.as_str(),
            body.push_key.as_deref(),
            body.app_id.as_deref(),
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    append_audit_log(
        state,
        Some(&session.actor),
        "push.unregister_device",
        json!({
            "device_id": body.device_id,
            "app_id": body.app_id,
            "removed_count": removed,
        }),
        if removed == 0 { "no_match" } else { "accepted" },
    )
    .await;
    json_ok(arkret_models_integration::models_push::PushUnregisterDeviceOutcome { ok: true })
}

#[salvo::oapi::endpoint(operation_id = "ak.edge.push.command.notify", tags("interop"))]
#[tracing::instrument(skip_all, fields(op = "ak.edge.push.command.notify"))]
pub(super) async fn push_notify(
    body: JsonBody<PushNotifyRequestBody>,
    depot: &mut Depot,
) -> JsonResult<PushNotifyOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    // The SDK owns the closed-shape rules for this body (push-notifications.md
    // and push-operations.schema.json): the notification must satisfy one of
    // the blind / visible oneOf branches, both of which require
    // timing_profile_hint. Without this call a body satisfying neither branch
    // was accepted, because the field is Option on the wire type and nothing
    // here checked it.
    arkret_models_integration::models_push::validate_push_notify_contract_shape(&body)
        .map_err(AppError::param_invalid)?;
    let push_target_id = body
        .notification
        .push_target_id
        .as_deref()
        .filter(|value| arkret_push_policy::blind_payload_sanitizer::is_valid_push_target_id(value))
        .ok_or_else(|| AppError::param_invalid("notification.push_target_id is required"))?;
    let devices = body.notification.devices.clone();
    let notification = serde_json::to_value(&body.notification).map_err(|error| {
        AppError::internal(format!("push notification request serialize: {error}"))
    })?;
    if push_notification_leaks_private_payload(&notification, None) {
        return Err(AppError::param_invalid(
            "push notification must not include plaintext content or stable identifiers",
        ));
    }
    let registered = state.deliveries().push_devices().await.unwrap_or_default();
    let mut outcomes = Vec::with_capacity(devices.len());
    let max_age = chrono::Duration::hours(PUSH_GATEWAY_CONTRACT_MAX_AGE_HOURS);
    for device in devices {
        let device_id = device.device_id.as_str();
        let Some(registered_device) = registered
            .iter()
            .filter(|registered| registered["device_id"].as_str() == Some(device_id))
            .find(|registered| push_registration_accepts_target(registered, push_target_id, now()))
        else {
            let has_device = registered
                .iter()
                .any(|registered| registered["device_id"].as_str() == Some(device_id));
            let reason = if has_device {
                arkret_models_integration::models_push::PushNotifyReasonCode::PushTargetUnknown
            } else {
                arkret_models_integration::models_push::PushNotifyReasonCode::PushTokenUnknown
            };
            outcomes.push(
                arkret_models_integration::models_push::PushNotifyDeviceOutcome::rejected(
                    device.device_id,
                    reason,
                    None,
                ),
            );
            continue;
        };
        let actor = registered_device
            .get("actor")
            .and_then(|value| value.as_str())
            .unwrap_or_default();

        // C33.1 fail-closed: every push fan-out must be backed by a trusted,
        // fresh gateway-contract snapshot. Anything other than `Match` is a
        // hard reject (no notify is sent, an audit row is appended, the
        // device shows up in `rejected`).
        let push_gateway_url = registered_device
            .get("push_gateway")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let drift = verify_push_gateway_contract_drift(state, push_gateway_url, max_age).await;
        // C33.1 fail-closed semantics — production must reject anything but
        // `Match`. Development mode (which has no real push bridge cache
        // warmed) treats `Unknown` as a soft pass so local fixtures don't
        // need to pre-load the cache.
        let drift_blocks = match drift {
            DriftResult::Match => false,
            DriftResult::Unknown => !state.config().development_mode,
            _ => true,
        };
        if drift_blocks {
            let drift_label = drift.as_str();
            append_audit_log(
                state,
                Some(actor),
                "push.notify.contract_drift_rejected",
                json!({
                    "device_id": device_id,
                    "push_gateway": push_gateway_url,
                    "drift_result": drift_label,
                }),
                "rejected",
            )
            .await;
            outcomes.push(
                arkret_models_integration::models_push::PushNotifyDeviceOutcome::rejected(
                    device.device_id,
                    arkret_models_integration::models_push::PushNotifyReasonCode::DeliveryBindingStale,
                    None,
                ),
            );
            continue;
        }
        outcomes.push(
            arkret_models_integration::models_push::PushNotifyDeviceOutcome::accepted(
                device.device_id,
            ),
        );
    }
    json_ok(PushNotifyOutcome {
        push_target_id: push_target_id.to_owned(),
        outcomes,
    })
}

/// Resolve the gateway URL of a registered device into a `bridge_describe_url`
/// and ask `PushBridgeCacheStore::verify_contract_freshness` whether the
/// persisted snapshot is trusted + fresh + matches its own digest. Returns
/// `Unknown` (fail-closed) when the gateway URL is empty or doesn't parse,
/// and when no snapshot has been persisted yet.
async fn verify_push_gateway_contract_drift(
    state: &AppState,
    push_gateway_url: &str,
    max_age: chrono::Duration,
) -> DriftResult {
    let trimmed = push_gateway_url.trim();
    if trimmed.is_empty() {
        return DriftResult::Unknown;
    }
    let Some(service_base_url) = derive_push_gateway_service_base_url(trimmed) else {
        return DriftResult::Unknown;
    };
    let bridge_describe_url =
        join_push_gateway_url(&service_base_url, "/_floria/push/bridge/describe");
    let service = state.deliveries();
    let snapshot_digest = match service
        .current_push_bridge_contract(&bridge_describe_url)
        .await
    {
        Ok(Some(record)) => record.contract_digest,
        Ok(None) => return DriftResult::Unknown,
        Err(error) => {
            tracing::error!(%error, "failed to read push bridge cache snapshot");
            return DriftResult::Unknown;
        }
    };
    if snapshot_digest.is_empty() {
        return DriftResult::Unknown;
    }
    service
        .verify_push_bridge_contract_freshness(&bridge_describe_url, &snapshot_digest, max_age)
        .await
        .unwrap_or(DriftResult::Unknown)
}

fn push_notification_leaks_private_payload(
    value: &serde_json::Value,
    parent_key: Option<&str>,
) -> bool {
    match value {
        serde_json::Value::Object(object) => object.iter().any(|(key, value)| {
            if parent_key == Some("devices")
                && matches!(key.as_str(), "device_id" | "push_key" | "app_id")
            {
                return false;
            }
            matches!(
                key.as_str(),
                "title"
                    | "body"
                    | "preview"
                    | "content"
                    | "plaintext"
                    | "message"
                    | "event_id"
                    | "realm_id"
                    | "space_id"
                    | "strand_id"
                    | "thread_id"
                    | "sender"
                    | "sender_actor_display_name"
                    | "sender_did"
                    | "sender_display_name"
                    | "space_name"
                    | "kind"
            ) || push_notification_leaks_private_payload(value, Some(key.as_str()))
        }),
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| push_notification_leaks_private_payload(value, parent_key)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_target_derivation_is_pairwise_and_stable() {
        let root_key = [7u8; 32];
        let epoch = "ak.push.salt_epoch.42";
        let first = derive_push_target_id(
            &root_key,
            "did:web:soland.example",
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-000000000001",
            "inkson.web",
            epoch,
        )
        .unwrap();
        let again = derive_push_target_id(
            &root_key,
            "did:web:soland.example",
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-000000000001",
            "inkson.web",
            epoch,
        )
        .unwrap();
        let other_route = derive_push_target_id(
            &root_key,
            "did:web:soland.example",
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-000000000001",
            "inkson.voip",
            epoch,
        )
        .unwrap();
        let other_service = derive_push_target_id(
            &root_key,
            "did:web:org.example",
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-000000000001",
            "inkson.web",
            epoch,
        )
        .unwrap();

        assert_eq!(first, again);
        assert_ne!(first, other_route);
        assert_ne!(first, other_service);
        assert!(arkret_push_policy::blind_payload_sanitizer::is_valid_push_target_id(&first));
        assert!(!first.contains("alice"));
        assert!(!first.contains("device"));
    }

    #[test]
    fn retained_push_target_acceptance_is_time_bounded() {
        let current = "ak:pseudonym:push:aaaaaaaaaaaaaaaaaaaaaa";
        let retained = "ak:pseudonym:push:bbbbbbbbbbbbbbbbbbbbbb";
        let now = chrono::DateTime::parse_from_rfc3339("2026-06-19T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let registration = json!({
            "push_target_id": current,
            "retained_push_targets": [{
                "push_target_id": retained,
                "salt_epoch_id": "ak.push.salt_epoch.41",
                "retained_until": "2026-06-19T01:00:00.000Z"
            }]
        });

        assert!(push_registration_accepts_target(
            &registration,
            current,
            now
        ));
        assert!(push_registration_accepts_target(
            &registration,
            retained,
            now
        ));
        assert!(!push_registration_accepts_target(
            &registration,
            retained,
            now + chrono::Duration::hours(2)
        ));
        assert!(!push_registration_accepts_target(
            &registration,
            "ak:pseudonym:push:cccccccccccccccccccccc",
            now
        ));
    }
}
