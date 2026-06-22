use super::signature::{
    applet_content_digest_header, applet_http_signature_base, applet_source_signature_anchor,
    applet_validate_signature_params,
};
use serde_json::json;

fn params(created: i64, expires: i64) -> String {
    format!(
        "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \
         \"source-service-did\" \"destination-service-did\" \"idempotency-key\");\
         created={created};expires={expires};keyid=\"did:web:app#applet-service-key\";\
         alg=\"ed25519\""
    )
}

/// COT-03-001: the §7.3.1 content-digest helper MUST emit the RFC 9421
/// `sha-256=:<base64>:` structured form, not the `sha256:<hex>` digest.
#[test]
fn content_digest_header_is_rfc9421_structured() {
    let header = applet_content_digest_header(b"{}");
    assert!(header.starts_with("sha-256=:"));
    assert!(header.ends_with(':'));
    assert!(!header.contains("sha256:"));
}

/// The signature base MUST cover the §7.3.1 header set in order.
#[test]
fn signature_base_covers_required_components() {
    let base = applet_http_signature_base(
        "POST",
        "https://edge.example/_cokret/edge/applet/transactions",
        "edge.example",
        "sha-256=:abc=:",
        "did:web:app",
        "did:web:edge",
        "idem-1",
        &params(0, 0),
    );
    for needle in [
        "\"@method\": POST",
        "\"@target-uri\":",
        "\"@authority\": edge.example",
        "\"content-digest\": sha-256=:abc=:",
        "\"source-service-did\": did:web:app",
        "\"destination-service-did\": did:web:edge",
        "\"idempotency-key\": idem-1",
        "\"@signature-params\":",
    ] {
        assert!(base.contains(needle), "base missing {needle}:\n{base}");
    }
}

/// keyid mismatch is `http_signature_invalid` (not a window error).
#[test]
fn keyid_mismatch_is_invalid_signature() {
    let now = chrono::Utc::now().timestamp();
    let err = applet_validate_signature_params(
        &params(now, now + 60),
        "did:web:other#applet-service-key",
    )
    .expect_err("keyid mismatch must fail");
    assert_eq!(
        err.top_level_reason.as_deref(),
        Some("http_signature_invalid")
    );
}

/// A fresh, well-formed window passes param validation.
#[test]
fn fresh_window_validates() {
    let now = chrono::Utc::now().timestamp();
    applet_validate_signature_params(&params(now, now + 60), "did:web:app#applet-service-key")
        .expect("fresh window must validate");
}

/// An ancient window is `signature_window_invalid`.
#[test]
fn ancient_window_is_window_invalid() {
    let err = applet_validate_signature_params(
        &params(1_000_000_000, 1_000_000_200),
        "did:web:app#applet-service-key",
    )
    .expect_err("ancient window must fail");
    assert_eq!(
        err.top_level_reason.as_deref(),
        Some("signature_window_invalid")
    );
}

/// An over-wide window (> 300s) is `signature_window_invalid`.
#[test]
fn overwide_window_is_window_invalid() {
    let now = chrono::Utc::now().timestamp();
    let err =
        applet_validate_signature_params(&params(now, now + 600), "did:web:app#applet-service-key")
            .expect_err("over-wide window must fail");
    assert_eq!(
        err.top_level_reason.as_deref(),
        Some("signature_window_invalid")
    );
}

#[test]
fn source_signature_anchor_binds_registration_epoch_and_webhook_auth() {
    let webhook_auth = json!({
        "type": "http_message_signature",
        "key_ref": "did:web:app#applet-service-key",
        "accepted_algs": ["EdDSA"]
    });
    let base = applet_source_signature_anchor(
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
    let epoch_rotated = applet_source_signature_anchor(
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
    let key_rotated = applet_source_signature_anchor(
        "did:web:app",
        "did:web:edge",
        "idem-1",
        "sha-256=:abc=:",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "did:web:app#rotated",
        json!("sha256:2222222222222222222222222222222222222222222222222222222222222222"),
        json!({
            "type": "http_message_signature",
            "key_ref": "did:web:app#rotated",
            "accepted_algs": ["EdDSA"]
        }),
        "ed25519",
        &params(1, 60),
        "sig1=:abc:",
    );

    assert_ne!(base, epoch_rotated);
    assert_ne!(base, key_rotated);
}
