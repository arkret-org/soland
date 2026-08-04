//! Shared helpers for the `push_keys` domain submodules.
//!
//! Reached from sibling cluster files via `use super::helpers::*;`.

use crate::common::*;

// `presence_event` is gone with the plaintext ephemeral rail: `signal.md` §1
// leaves the server no presence projection to read out of a sync frame.

pub(crate) fn account_data_entry<'a>(sync: &'a Value, account_data_key: &str) -> Option<&'a Value> {
    sync["account_data"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["account_data_key"] == account_data_key)
}

pub(crate) fn device_message_target(kind: &str, content: Value) -> Value {
    serde_json::json!({
        "message_id": new_prefixed_uuid7("ak:device_message:"),
        "kind": kind,
        "content": content,
        "expires_at": arkret_canonical::format_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::hours(1)
        ),
    })
}

pub(crate) fn signed_keys_upload_body(
    actor: &str,
    device_id: &str,
    signing_key: &SigningKey,
    one_time_keys: Value,
    fallback_keys: Value,
) -> Value {
    let unsigned: arkret_models_crypto::KeysUploadUnsignedRequest =
        serde_json::from_value(serde_json::json!({
            "device_id": device_id,
            "one_time_keys": one_time_keys,
            "fallback_keys": fallback_keys,
        }))
        .unwrap();
    let signing_input = arkret_models_crypto::keys_upload_signing_input(&unsigned).unwrap();
    let sig = arkret_canonical::base64url_encode(signing_key.sign(&signing_input).to_bytes());
    serde_json::to_value(
        unsigned.into_signed(arkret_models_crypto::KeyOperationSignature {
            kid: arkret_wire::NonEmptyString::new(format!("{actor}#device")).unwrap(),
            signature_algorithm: Some(arkret_wire::NonEmptyString::new("Ed25519").unwrap()),
            sig: arkret_wire::Base64UrlString::new(sig).unwrap(),
        }),
    )
    .unwrap()
}

// `seed_verified_device_with_public_key` moved to `crate::common`: the Signal
// rail needs the same authoritative device directory row, and `common` is the
// only module every domain submodule can reach.
