use std::fmt::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::Utc;
use ed25519_dalek::{Signature, SigningKey, Verifier as _, VerifyingKey};
use salvo::prelude::Request;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::AppError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalBodyDigests {
    pub(crate) content_digest: String,
    pub(crate) request_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SignatureWindowViolation {
    MissingCreated,
    MissingExpires,
    CreatedOutsideSkew,
    InvalidValidityWindow,
    Expired,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SignatureBaseComponent<'a> {
    name: &'static str,
    value: Option<&'a str>,
}

impl<'a> SignatureBaseComponent<'a> {
    pub(crate) fn required(name: &'static str, value: &'a str) -> Self {
        Self {
            name,
            value: Some(value),
        }
    }

    pub(crate) fn optional(name: &'static str, value: Option<&'a str>) -> Self {
        Self { name, value }
    }
}

pub(crate) fn rfc9530_content_digest(bytes: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(bytes)))
}

pub(crate) fn canonical_body_digests(
    value: &Value,
    canonical_error: impl FnOnce(String) -> AppError,
) -> Result<CanonicalBodyDigests, AppError> {
    let body_bytes = arkret_sdk::canonical::canonical_json_bytes(value)
        .map_err(|error| canonical_error(error.to_string()))?;
    Ok(CanonicalBodyDigests {
        content_digest: rfc9530_content_digest(&body_bytes),
        request_digest: arkret_sdk::canonical::sha256_digest(&body_bytes),
    })
}

pub(crate) fn required_header(
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

pub(crate) fn signature_params(
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

pub(crate) fn signature_param_value(signature_params: &str, key: &str) -> Option<String> {
    signature_params.split(';').skip(1).find_map(|part| {
        let (name, value) = part.split_once('=')?;
        if name.trim() != key {
            return None;
        }
        Some(value.trim().trim_matches('"').to_owned())
    })
}

pub(crate) fn validate_signature_freshness(
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

pub(crate) fn signature_base(
    components: &[SignatureBaseComponent<'_>],
    signature_params: &str,
) -> String {
    let mut base = String::new();
    for component in components {
        if let Some(value) = component.value {
            let _ = writeln!(base, "\"{}\": {}", component.name, value);
        }
    }
    let _ = write!(base, "\"@signature-params\": {signature_params}");
    base
}

pub(crate) fn verify_signature_header(
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
        .verify(signature_base.as_bytes(), &signature)
        .map_err(|_| verify_error())
}

pub(crate) fn decode_signature_header(value: &str) -> Result<Signature, &'static str> {
    let signature_b64 = value
        .strip_prefix("sig1=:")
        .and_then(|value| value.strip_suffix(':'))
        .ok_or("Signature header must use sig1=:base64: form")?;
    let signature_bytes = STANDARD
        .decode(signature_b64)
        .map_err(|_| "Signature header base64 is invalid")?;
    Signature::from_slice(&signature_bytes).map_err(|_| "Signature header is not Ed25519 length")
}

pub(crate) fn deterministic_development_signing_key(
    domain: &[u8],
    key_material: &str,
) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(key_material.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}
