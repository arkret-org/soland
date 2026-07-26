use soland_http::error::AppError;

use super::*;

const FEDERATION_AUTH_FAILURE_MESSAGE_FOR_TEST: &str = "federation request authentication failed";

fn verify_actor_body()
-> arkret_models_collaboration::federation::wire_dtos::FederationVerifyActorRequestBody {
    arkret_models_collaboration::federation::wire_dtos::FederationVerifyActorRequestBody {
        actor_id: arkret_identifiers::Did::new("did:web:alice.example").unwrap(),
        challenge: Some("challenge-1".to_owned()),
        signed_payload_digest: None,
        signature: arkret_models_collaboration::federation::frames::VerifyActorChallengeSignature {
            key_id: "did:web:alice.example#key-1".to_owned(),
            signature: "test-signature".to_owned(),
        },
        purpose: "federation.verify_actor".to_owned(),
        realm_id: None,
    }
}

fn trust_domain(value: &str) -> arkret_identifiers::TypedTrustDomainId {
    arkret_identifiers::TypedTrustDomainId::new(value.to_owned()).unwrap()
}

fn federation_headers(digest: &str) -> FederationTrustHeaders {
    FederationTrustHeaders {
        source_trust_domain: trust_domain("ak:trust_domain:peer.example"),
        destination_trust_domain: trust_domain("ak:trust_domain:soland.local"),
        request_canonical_digest: arkret_identifiers::Hash::new(digest.to_owned()).unwrap(),
    }
}

#[test]
fn verify_actor_digest_uses_canonical_json() {
    let body = verify_actor_body();
    let value = serde_json::to_value(&body).unwrap();
    let expected = arkret_canonical::canonical_sha256(&value).unwrap();

    assert_eq!(federation_verify_actor_digest(&body).unwrap(), expected);
}

#[test]
fn verify_actor_headers_accept_matching_canonical_digest() {
    let body = verify_actor_body();
    let digest = federation_verify_actor_digest(&body).unwrap();
    let headers = federation_headers(&digest);

    validate_federation_headers(
        &headers,
        &trust_domain("ak:trust_domain:soland.local"),
        &digest,
    )
    .expect("matching digest and destination accepted");
}

#[test]
fn verify_actor_headers_reject_digest_mismatch() {
    let body = verify_actor_body();
    let digest = federation_verify_actor_digest(&body).unwrap();
    let headers = federation_headers(&format!("sha256:{}", "0".repeat(64)));

    let error = validate_federation_headers(
        &headers,
        &trust_domain("ak:trust_domain:soland.local"),
        &digest,
    )
    .expect_err("mismatched digest rejected");

    assert_auth_rejection_is_minimal(error);
}

#[test]
fn verify_actor_headers_reject_destination_mismatch() {
    let body = verify_actor_body();
    let digest = federation_verify_actor_digest(&body).unwrap();
    let headers = federation_headers(&digest);

    let error = validate_federation_headers(
        &headers,
        &trust_domain("ak:trust_domain:other.example"),
        &digest,
    )
    .expect_err("wrong destination rejected");

    assert_auth_rejection_is_minimal(error);
}

const SIG_TEST_DID: &str = "did:web:test.local";

fn sig_params(extra: &str) -> String {
    format!(
        "sig1=(\"@method\");keyid=\"{SIG_TEST_DID}#federation-fanout-key\";alg=\"ed25519\"{extra}"
    )
}

#[test]
fn validate_signature_params_accepts_fresh_window() {
    let now = Utc::now().timestamp();
    let params = sig_params(&format!(";created={now};expires={}", now + 120));
    validate_signature_params(&params, SIG_TEST_DID, "test")
        .expect("fresh signature within ±30s / 300s window must pass");
}

#[test]
fn validate_signature_params_rejects_missing_created() {
    let now = Utc::now().timestamp();
    let params = sig_params(&format!(";expires={}", now + 120));
    let error = validate_signature_params(&params, SIG_TEST_DID, "test")
        .expect_err("missing created must fail closed");
    assert_auth_rejection_is_minimal(error);
}

#[test]
fn validate_signature_params_rejects_missing_expires() {
    let now = Utc::now().timestamp();
    let params = sig_params(&format!(";created={now}"));
    let error = validate_signature_params(&params, SIG_TEST_DID, "test")
        .expect_err("missing expires must fail closed");
    assert_auth_rejection_is_minimal(error);
}

#[test]
fn validate_signature_params_rejects_past_clock_skew() {
    let now = Utc::now().timestamp();
    let params = sig_params(&format!(";created={};expires={}", now - 60, now + 120));
    let error = validate_signature_params(&params, SIG_TEST_DID, "test")
        .expect_err("created beyond past skew must fail closed");
    assert_auth_rejection_is_minimal(error);
}

#[test]
fn validate_signature_params_rejects_future_clock_skew() {
    let now = Utc::now().timestamp();
    let params = sig_params(&format!(";created={};expires={}", now + 60, now + 120));
    let error = validate_signature_params(&params, SIG_TEST_DID, "test")
        .expect_err("created beyond future skew must fail closed");
    assert_auth_rejection_is_minimal(error);
}

#[test]
fn validate_signature_params_rejects_window_over_300s() {
    let now = Utc::now().timestamp();
    let params = sig_params(&format!(";created={now};expires={}", now + 400));
    let error = validate_signature_params(&params, SIG_TEST_DID, "test")
        .expect_err("validity window over 300s must fail closed");
    assert_auth_rejection_is_minimal(error);
}

#[test]
fn validate_signature_params_rejects_already_expired() {
    let now = Utc::now().timestamp();
    let params = sig_params(&format!(";created={};expires={}", now - 20, now - 1));
    let error = validate_signature_params(&params, SIG_TEST_DID, "test")
        .expect_err("already-expired signature must fail closed");
    assert_auth_rejection_is_minimal(error);
}

fn assert_auth_rejection_is_minimal(error: AppError) {
    assert_eq!(error.code, soland_http::error::ErrorCode::Unauthenticated);
    assert_eq!(error.wire_code(), "unauthenticated");
    assert_eq!(error.http_status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        error.message.as_ref(),
        FEDERATION_AUTH_FAILURE_MESSAGE_FOR_TEST
    );
}
