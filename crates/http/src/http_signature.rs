use chrono::Utc;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use salvo::prelude::Request;
use sha2::{Digest, Sha256};

use crate::error::AppError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalBodyDigests {
    pub content_digest: String,
    pub request_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureWindowViolation {
    MissingCreated,
    MissingExpires,
    CreatedOutsideSkew,
    InvalidValidityWindow,
    Expired,
}

#[derive(Clone, Copy, Debug)]
pub struct SignatureBaseComponent<'a> {
    name: &'static str,
    value: Option<&'a str>,
}

impl<'a> SignatureBaseComponent<'a> {
    pub fn required(name: &'static str, value: &'a str) -> Self {
        Self {
            name,
            value: Some(value),
        }
    }

    pub fn optional(name: &'static str, value: Option<&'a str>) -> Self {
        Self { name, value }
    }
}

pub fn rfc9530_content_digest(bytes: &[u8]) -> String {
    arkret_signatures::http_signature::ContentDigest::compute(
        bytes,
        arkret_signatures::http_signature::ContentDigestAlgorithm::Sha256,
    )
    .wire_value
}

pub fn exact_body_digests(body_bytes: &[u8]) -> CanonicalBodyDigests {
    CanonicalBodyDigests {
        content_digest: rfc9530_content_digest(body_bytes),
        request_digest: arkret_canonical::sha256_digest(body_bytes),
    }
}

pub fn validate_canonical_json_body(
    body_bytes: &[u8],
    canonical_error: impl FnOnce(String) -> AppError,
) -> Result<(), AppError> {
    arkret_signatures::http_signature::validate_signed_canonical_json_body(false, body_bytes)
        .map_err(|error| canonical_error(error.to_string()))
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

pub fn signature_params(
    req: &Request,
    header_name: &str,
    missing_error: impl FnOnce() -> AppError,
    invalid_error: impl FnOnce() -> AppError,
) -> Result<String, AppError> {
    req.headers()
        .get(header_name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(missing_error)?
        .strip_prefix("sig1=")
        .map(ToOwned::to_owned)
        .ok_or_else(invalid_error)
}

pub fn signature_param_value(signature_params: &str, key: &str) -> Option<String> {
    signature_params.split(';').skip(1).find_map(|part| {
        let (name, value) = part.split_once('=')?;
        if name.trim() != key {
            return None;
        }
        Some(value.trim().trim_matches('"').to_owned())
    })
}

pub fn validate_signature_freshness(
    signature_params: &str,
) -> Result<(), SignatureWindowViolation> {
    let now = Utc::now().timestamp();
    let created = signature_param_value(signature_params, "created")
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or(SignatureWindowViolation::MissingCreated)?;
    let expires = signature_param_value(signature_params, "expires")
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or(SignatureWindowViolation::MissingExpires)?;
    if (created - now).abs() > 30 {
        return Err(SignatureWindowViolation::CreatedOutsideSkew);
    }
    if expires < created || expires - created > 300 {
        return Err(SignatureWindowViolation::InvalidValidityWindow);
    }
    if expires < now {
        return Err(SignatureWindowViolation::Expired);
    }
    Ok(())
}

pub fn signature_base(components: &[SignatureBaseComponent<'_>], signature_params: &str) -> String {
    let components = components
        .iter()
        .filter_map(|component| {
            component.value.map(|value| {
                (
                    arkret_signatures::http_signature::Component::parse(component.name),
                    value.to_owned(),
                )
            })
        })
        .collect::<Vec<_>>();
    String::from_utf8(
        arkret_signatures::http_signature::canonical_message_from_component_values(
            &components,
            signature_params,
        ),
    )
    .expect("RFC 9421 canonical message is UTF-8")
}

pub fn verify_signature_header(
    req: &Request,
    header_name: &str,
    signature_base: &str,
    missing_error: impl FnOnce(&str) -> AppError,
    decode_error: impl FnOnce(&'static str) -> AppError,
    verify_error: impl FnOnce() -> AppError,
    resolve_key: impl FnOnce() -> Result<VerifyingKey, AppError>,
) -> Result<(), AppError> {
    let signature_header = required_header(req, header_name, missing_error)?;
    let signature = decode_signature_header(&signature_header).map_err(decode_error)?;
    let verifying_key = resolve_key()?;
    verifying_key
        .verify_strict(signature_base.as_bytes(), &signature)
        .map_err(|_| verify_error())
}

pub fn decode_signature_header(value: &str) -> Result<Signature, &'static str> {
    let signature_bytes = arkret_signatures::http_signature::parse_signature_header(value, "sig1")
        .map_err(|_| "Signature header must contain a valid sig1 byte sequence")?;
    Signature::from_slice(&signature_bytes).map_err(|_| "Signature header is not Ed25519 length")
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
    fn exact_body_digests_cover_exact_wire_bytes() {
        let body = br#"{"a":1,"b":2}"#;
        let digests = exact_body_digests(body);

        assert_eq!(digests.content_digest, rfc9530_content_digest(body));
        assert_eq!(
            digests.request_digest,
            arkret_canonical::sha256_digest(body)
        );
        assert!(digests.content_digest.starts_with("sha-256=:"));
    }

    #[test]
    fn canonical_json_validation_rejects_parse_then_canonicalize_variants() {
        for body in [
            br#"{ "a": 1, "b": 2 }"#.as_slice(),
            br#"{"b":2,"a":1}"#.as_slice(),
            br#"{"a":1,"a":1}"#.as_slice(),
        ] {
            assert!(
                validate_canonical_json_body(body, AppError::invalid_param).is_err(),
                "non-canonical wire body must be rejected: {}",
                String::from_utf8_lossy(body)
            );
        }
    }

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
