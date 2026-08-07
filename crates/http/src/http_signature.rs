use ed25519_dalek::SigningKey;
use salvo::prelude::Request;
use sha2::{Digest, Sha256};

use crate::error::AppError;

pub fn rfc9530_content_digest(bytes: &[u8]) -> String {
    arkret_signatures::http_signature::ContentDigest::compute(
        bytes,
        arkret_signatures::http_signature::ContentDigestAlgorithm::Sha256,
    )
    .wire_value
}

pub fn reject_content_encoding(
    req: &Request,
    encoded_error: impl FnOnce() -> AppError,
) -> Result<(), AppError> {
    arkret_signatures::http_signature::validate_signed_canonical_json_body(
        req.headers().contains_key("content-encoding"),
        b"{}",
    )
    .map_err(|_| encoded_error())
}

pub fn required_header(
    req: &Request,
    name: &str,
    missing_error: impl FnOnce(&str) -> AppError,
) -> Result<String, AppError> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| missing_error(name))
}

pub fn parse_signature_input_header(
    req: &Request,
) -> Result<
    arkret_signatures::http_signature::SignatureInput,
    arkret_signatures::http_signature::HttpMessageVerificationError,
> {
    let header = req
        .headers()
        .get("signature-input")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(
            arkret_signatures::http_signature::HttpMessageVerificationError::MissingHeader(
                "Signature-Input",
            ),
        )?;
    arkret_signatures::http_signature::parse_signature_input(header).map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_signed_http_request(
    req: &Request,
    target_uri: &str,
    authority: &str,
    body: &[u8],
    public_key: &arkret_signatures::http_signature::Ed25519PublicKey,
    policy: &arkret_signatures::http_signature::SignatureVerificationPolicy,
) -> Result<
    arkret_signatures::http_signature::VerifiedHttpMessageSignature,
    arkret_signatures::http_signature::HttpMessageVerificationError,
> {
    let headers = request_headers(req);
    arkret_signatures::http_signature::verify_signed_http_message(
        req.method().as_str(),
        target_uri,
        authority,
        req.uri().path(),
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        body,
        public_key,
        policy,
        chrono::Utc::now().timestamp(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_signed_canonical_json_request(
    req: &Request,
    target_uri: &str,
    authority: &str,
    body: &[u8],
    public_key: &arkret_signatures::http_signature::Ed25519PublicKey,
    policy: &arkret_signatures::http_signature::SignatureVerificationPolicy,
) -> Result<
    arkret_signatures::http_signature::VerifiedHttpMessageSignature,
    arkret_signatures::http_signature::HttpMessageVerificationError,
> {
    let headers = request_headers(req);
    arkret_signatures::http_signature::verify_signed_canonical_json_message(
        req.method().as_str(),
        target_uri,
        authority,
        req.uri().path(),
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        req.headers().contains_key("content-encoding"),
        body,
        public_key,
        policy,
        chrono::Utc::now().timestamp(),
    )
}

fn request_headers(req: &Request) -> Vec<(String, String)> {
    req.headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect()
}

pub fn deterministic_development_signing_key(domain: &[u8], key_material: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(key_material.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_json_rejects_content_encoding() {
        let mut request = Request::new();
        request.headers_mut().insert(
            "content-encoding",
            salvo::http::HeaderValue::from_static("gzip"),
        );

        assert!(reject_content_encoding(&request, || AppError::invalid_param("encoded")).is_err());
    }
}
