//! Integration tests — production Ed25519 JWS verifier.
//!
//! dev-login is gated by `config.development_mode=true`, so we can't use
//! the HTTP path with auth tokens to test the production verifier. Instead
//! we exercise the verifier directly via the public `soland::jws_verify`
//! module. AppState is built minimally with `development_mode=false` so
//! the DID resolver is identical to production-deploy behaviour.

use ed25519_dalek::{Signer, SigningKey};

use super::common::*;

/// Encode an Ed25519 public key as the multibase form did:key + DID
/// Document verificationMethod entries use:
/// `z<base58btc(0xed 0x01 || pubkey32)>`.
fn encode_ed25519_multibase(pubkey: &[u8; 32]) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.push(0xed);
    bytes.push(0x01);
    bytes.extend_from_slice(pubkey);
    format!("z{}", bs58::encode(&bytes).into_string())
}

/// Build a JWS detached signature over `canonical_bytes` with `signing_key`.
/// Returns `(jws, payload_digest_hex)`.
fn make_detached_jws(signing_key: &SigningKey, canonical_bytes: &[u8], tamper: bool) -> String {
    let header_json = br#"{"alg":"EdDSA"}"#;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(canonical_bytes);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let mut signature = signing_key.sign(signing_input.as_bytes()).to_bytes();
    if tamper {
        signature[0] ^= 0xff;
    }
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature);
    format!("{header_b64}..{sig_b64}")
}

#[tokio::test]
async fn production_verifier_accepts_real_ed25519_did_key_signature() {
    let mut cfg = test_config();
    cfg.development_mode = false;
    let state = AppState::new(cfg, Db { pool: None });

    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let multibase = encode_ed25519_multibase(&pubkey_bytes);
    let did = format!("did:key:{}", multibase);
    let verification_method = format!("{did}#{multibase}");

    let canonical_bytes = b"some canonical move bytes for testing";
    let jws = make_detached_jws(&signing_key, canonical_bytes, false);

    let result = soland::jws_verify::verify_jws_ed25519(
        canonical_bytes,
        &jws,
        &verification_method,
        &did,
        &state,
    );
    assert!(
        result.is_ok(),
        "real-Ed25519-signed JWS over did:key should verify; got {result:?}"
    );
}

#[tokio::test]
async fn production_verifier_rejects_tampered_signature() {
    let mut cfg = test_config();
    cfg.development_mode = false;
    let state = AppState::new(cfg, Db { pool: None });

    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let multibase = encode_ed25519_multibase(&pubkey_bytes);
    let did = format!("did:key:{}", multibase);
    let verification_method = format!("{did}#{multibase}");

    let canonical_bytes = b"another canonical payload";
    let jws = make_detached_jws(&signing_key, canonical_bytes, true);

    let result = soland::jws_verify::verify_jws_ed25519(
        canonical_bytes,
        &jws,
        &verification_method,
        &did,
        &state,
    );
    let err = result.expect_err("tampered signature MUST be rejected");
    assert!(
        err.to_ascii_lowercase().contains("verify failed")
            || err.to_ascii_lowercase().contains("ed25519")
            || err.to_ascii_lowercase().contains("signature"),
        "rejection reason should mention the signature failure (got `{err}`)"
    );
}

#[tokio::test]
async fn production_verifier_rejects_signature_over_different_payload() {
    let mut cfg = test_config();
    cfg.development_mode = false;
    let state = AppState::new(cfg, Db { pool: None });

    let signing_key = SigningKey::from_bytes(&[13u8; 32]);
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let multibase = encode_ed25519_multibase(&pubkey_bytes);
    let did = format!("did:key:{}", multibase);
    let verification_method = format!("{did}#{multibase}");

    // Sign payload A but try to verify against payload B — proves the
    // verifier actually binds the signature to the canonical_bytes input,
    // not just shape.
    let signed_bytes = b"the canonical bytes the signer signed";
    let jws = make_detached_jws(&signing_key, signed_bytes, false);
    let claimed_bytes = b"DIFFERENT bytes the verifier was given";

    let result = soland::jws_verify::verify_jws_ed25519(
        claimed_bytes,
        &jws,
        &verification_method,
        &did,
        &state,
    );
    assert!(
        result.is_err(),
        "verifier MUST reject when canonical_bytes don't match the signed input"
    );
}

#[tokio::test]
async fn production_verifier_rejects_unknown_verification_method() {
    let mut cfg = test_config();
    cfg.development_mode = false;
    let state = AppState::new(cfg, Db { pool: None });

    let signing_key = SigningKey::from_bytes(&[17u8; 32]);
    let canonical_bytes = b"some payload";
    let jws = make_detached_jws(&signing_key, canonical_bytes, false);

    // verification_method points at a did:web that the resolver chain
    // can't reach (would need an HTTP fetch in test env).
    let result = soland::jws_verify::verify_jws_ed25519(
        canonical_bytes,
        &jws,
        "did:web:unreachable.example#k1",
        "did:web:unreachable.example",
        &state,
    );
    assert!(
        result.is_err(),
        "verifier MUST fail when DID resolution can't produce a verification method"
    );
}
