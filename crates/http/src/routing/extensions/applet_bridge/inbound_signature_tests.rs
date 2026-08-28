use serde_json::json;

use super::signature::{
    applet_delivery_authentication_record_digest, applet_validate_signature_input,
};

fn params(created: i64, expires: i64) -> String {
    format!(
        "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \
         \"source-service-id\" \"destination-service-id\" \"idempotency-key\");\
         created={created};expires={expires};keyid=\"did:web:app#applet-service-key\";\
         alg=\"ed25519\""
    )
}

/// COT-03-001: the §7.3.1 content-digest helper MUST emit the RFC 9421
/// `sha-256=:<base64>:` structured form, not the `sha256:<hex>` digest.
#[test]
fn content_digest_header_is_rfc9421_structured() {
    let header = crate::routing::federation::rfc9530_content_digest(b"{}");
    assert!(header.starts_with("sha-256=:"));
    assert!(header.ends_with(':'));
    assert!(!header.contains("sha256:"));
}

/// keyid mismatch is `http_signature_invalid` (not a window error).
#[test]
fn keyid_mismatch_is_invalid_signature() {
    let now = chrono::Utc::now().timestamp();
    let input = arkret_signatures::http_signature::parse_signature_input(&format!(
        "sig1={}",
        params(now, now + 60)
    ))
    .unwrap();
    let err = applet_validate_signature_input(&input, "did:web:other#applet-service-key")
        .expect_err("keyid mismatch must fail");
    assert_eq!(
        err.code,
        soland_http::error::ErrorCode::HttpSignatureInvalid
    );
}

#[test]
fn delivery_authentication_record_digest_binds_registration_epoch_and_webhook_auth() {
    let webhook_auth = json!({
        "kind": "http_message_signature",
        "key_ref": "did:web:app#applet-service-key",
        "accepted_signature_algorithms": ["ed25519"]
    });
    let base = applet_delivery_authentication_record_digest(
        "did:web:app",
        "did:web:edge",
        "idem-1",
        "sha-256=:abc=:",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "did:web:app#applet-service-key",
        json!("sha256:2222222222222222222222222222222222222222222222222222222222222222"),
        webhook_auth.clone(),
        "ed25519",
        &params(1, 60),
        "sig1=:abc:",
    );
    let epoch_rotated = applet_delivery_authentication_record_digest(
        "did:web:app",
        "did:web:edge",
        "idem-1",
        "sha-256=:abc=:",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "did:web:app#applet-service-key",
        json!("sha256:3333333333333333333333333333333333333333333333333333333333333333"),
        webhook_auth,
        "ed25519",
        &params(1, 60),
        "sig1=:abc:",
    );
    let key_rotated = applet_delivery_authentication_record_digest(
        "did:web:app",
        "did:web:edge",
        "idem-1",
        "sha-256=:abc=:",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "did:web:app#rotated",
        json!("sha256:2222222222222222222222222222222222222222222222222222222222222222"),
        json!({
            "kind": "http_message_signature",
            "key_ref": "did:web:app#rotated",
            "accepted_signature_algorithms": ["ed25519"]
        }),
        "ed25519",
        &params(1, 60),
        "sig1=:abc:",
    );

    assert_ne!(base, epoch_rotated);
    assert_ne!(base, key_rotated);
}
