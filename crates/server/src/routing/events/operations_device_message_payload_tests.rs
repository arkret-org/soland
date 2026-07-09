use serde_json::json;

use super::*;

fn device_message_target(kind: &str, content: Value) -> DeviceMessageTarget {
    DeviceMessageTarget {
        kind: kind.to_owned(),
        content,
        expires_at: "2026-06-10T00:10:00Z".parse().expect("valid timestamp"),
    }
}

/// device-lifecycle.md §7 permits cleartext to-device content for
/// verification bootstrap; the queue is zero-knowledge and MUST NOT force
/// the MLS Realm `encrypted_envelope` shape on these.
#[test]
fn accepts_cleartext_verification_content() {
    let payload = device_message_target(
        "ak.key.verification.key",
        json!({"transaction_id": "ver_1", "from_device": "ak:device:x", "key": "base64"}),
    );
    assert!(validate_device_message_target(&payload).is_ok());
}

/// §10.7 `ck.secret.request` carries only a one-time HPKE public key in
/// cleartext; `ck.secret.send` is HPKE-sealed under its own shape. Both MUST
/// pass the transport-shape validator.
#[test]
fn accepts_secret_share_content() {
    let request = device_message_target(
        "ak.secret.request",
        json!({
            "request_id": "r1",
            "secret_id": "inkson_mls_account_secret",
            "from_device": "ak:device:new",
            "recipient_hpke_public_key": "cHVi"
        }),
    );
    assert!(validate_device_message_target(&request).is_ok());

    let send = device_message_target(
        "ak.secret.send",
        json!({
            "request_id": "r1",
            "secret_id": "inkson_mls_account_secret",
            "from_device": "ak:device:old",
            "scheme": "ak.hpke_x25519_aead_chacha20poly1305.v1",
            "enc": "ZW5j",
            "ciphertext": "Y2lwaGVy"
        }),
    );
    assert!(validate_device_message_target(&send).is_ok());
}

/// Transport shape is still enforced: a blank kind or a non-object content
/// is rejected. ("missing content" is now impossible — `DeviceMessageTarget`
/// makes `content` a required field, enforced by serde before this runs.)
#[test]
fn rejects_blank_kind_or_non_object_content() {
    assert_eq!(
        validate_device_message_target(&device_message_target("", json!({}))),
        Err("device message requires kind")
    );
    assert_eq!(
        validate_device_message_target(&device_message_target(
            "ak.secret.request",
            json!("not-an-object")
        )),
        Err("device message content must be a JSON object")
    );
}
