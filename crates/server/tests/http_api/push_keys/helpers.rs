//! Shared helpers for the `push_keys` domain submodules.
//!
//! Reached from sibling cluster files via `use super::helpers::*;`.

#![allow(unused_imports)]
use crate::common::*;

pub(crate) fn presence_event<'a>(sync: &'a Value, actor: &str) -> &'a Value {
    sync["presence"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["actor_id"] == actor || event["user_id"] == actor)
        .expect("presence event present in account subscribe frame")
}

pub(crate) fn account_data_entry<'a>(sync: &'a Value, data_type: &str) -> Option<&'a Value> {
    sync["account_data"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["data_type"] == data_type)
}

pub(crate) fn device_message_target(kind: &str, content: Value) -> Value {
    serde_json::json!({
        "kind": kind,
        "content": content,
        "expires_at": (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    })
}

pub(crate) fn keys_upload_signing_input(
    device_id: &str,
    one_time_keys: &Value,
    fallback_keys: &Value,
) -> Vec<u8> {
    let body = serde_json::json!({
        "device_id": device_id,
        "one_time_keys": one_time_keys,
        "fallback_keys": fallback_keys,
    });
    let canonical = arkret_sdk::canonical::canonical_json_bytes(&body).unwrap();
    let mut input = b"ak.keys-upload-v1\n".to_vec();
    input.extend_from_slice(&canonical);
    input
}

pub(crate) fn signed_keys_upload_body(
    actor: &str,
    device_id: &str,
    signing_key: &SigningKey,
    one_time_keys: Value,
    fallback_keys: Value,
) -> Value {
    let signing_input = keys_upload_signing_input(device_id, &one_time_keys, &fallback_keys);
    let sig = arkret_sdk::base64url_encode(signing_key.sign(&signing_input).to_bytes());
    serde_json::json!({
        "device_id": device_id,
        "one_time_keys": one_time_keys,
        "fallback_keys": fallback_keys,
        "device_signature": {
            "alg": "EdDSA",
            "kid": format!("{actor}#device"),
            "sig": sig,
        }
    })
}

/// Persist a verified device for `actor` carrying an authoritative
/// `device_public_key` (the shape the session-grant exchange and the
/// `ak.device.authorize` projection both write), so the `keys/query`
/// signing-key directory can resolve it.
pub(crate) async fn seed_verified_device_with_public_key(
    state: &AppState,
    actor: &str,
    device_id: &str,
    device_public_key: &str,
) {
    let now = chrono::Utc::now();
    state
        .persistence
        .devices()
        .put(&soland::state::DeviceInventoryRecord {
            actor: actor.to_owned(),
            device_id: device_id.to_owned(),
            display_name: Some("Directory Test Device".to_owned()),
            verification_state: "verified".to_owned(),
            payload: serde_json::json!({
                "device_id": device_id,
                "verification": "verified",
                "device_public_key": device_public_key,
                "device_authorize_event_id": "ak:event:01904100-0000-7000-8000-a11ce00000aa",
                "enrollment_authority_binding": {
                    "kind": "service_attested",
                    "authority_did": "did:web:auth.example",
                    "authorization_ref": format!("{actor}#device-enrollment")
                }
            }),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
}
