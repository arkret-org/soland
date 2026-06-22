use std::cell::RefCell;
use std::time::{Duration as StdDuration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{Signature, SigningKey, Verifier as _, VerifyingKey};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::outbound::content_digest_header;
use super::wire::FederationTrustHeaders;
use crate::error::AppError;
use crate::state::AppState;

pub(super) const FEDERATION_AUTH_FAILURE_MESSAGE: &str = "federation request authentication failed";
const FEDERATION_AUTH_FAILURE_TIMING_BUCKET: StdDuration = StdDuration::from_millis(80);

thread_local! {
    static FEDERATION_AUTH_TIMING_STARTED_AT: RefCell<Option<Instant>> = RefCell::new(None);
}

struct FederationAuthTimingGuard {
    previous: Option<Instant>,
}

impl FederationAuthTimingGuard {
    fn enter() -> Self {
        let now = Instant::now();
        let previous =
            FEDERATION_AUTH_TIMING_STARTED_AT.with(|started_at| started_at.replace(Some(now)));
        Self { previous }
    }
}

impl Drop for FederationAuthTimingGuard {
    fn drop(&mut self) {
        FEDERATION_AUTH_TIMING_STARTED_AT.with(|started_at| {
            started_at.replace(self.previous.take());
        });
    }
}

pub(super) fn validate_federation_request_binding(
    trust_domain: &str,
    req: &Request,
    request_hash: &str,
) -> Result<(), AppError> {
    let headers = FederationTrustHeaders::from_salvo_request(req).map_err(|violation| {
        signature_error(format!(
            "federation trust header validation failed: {}",
            violation.message()
        ))
    })?;
    let expected_destination = cokret_sdk::TypedTrustDomainId::new(trust_domain.to_owned())
        .map_err(|error| AppError::internal(format!("configured trust_domain invalid: {error}")))?;
    validate_federation_headers(&headers, &expected_destination, request_hash)
}

pub(super) fn validate_federation_headers(
    headers: &FederationTrustHeaders,
    expected_destination: &cokret_sdk::TypedTrustDomainId,
    request_hash: &str,
) -> Result<(), AppError> {
    headers
        .verify_destination(expected_destination)
        .map_err(|_| {
            cross_domain_replay_error(
                "federation Destination-Trust-Domain header does not match this service",
            )
        })?;
    if request_hash != headers.request_canonical_digest.as_str() {
        crate::metrics::record_digest_mismatch("federation_request_binding");
        return Err(cross_domain_replay_error(
            "Request-Canonical-Digest does not match the canonical request body",
        ));
    }
    Ok(())
}

pub(super) fn verify_inbound_push_http_signature(
    state: &AppState,
    req: &Request,
    body: &cokret_sdk::FederationPushOperationsRequestBody,
) -> Result<(), AppError> {
    let body_value = serde_json::to_value(body).map_err(|error| {
        AppError::internal(format!(
            "federation push body serialization failed: {error}"
        ))
    })?;
    verify_inbound_federation_http_signature(
        state,
        req,
        &body_value,
        body.origin.as_str(),
        body.destination.as_str(),
        "federation_push",
    )
}

pub(super) fn verify_inbound_transaction_http_signature(
    state: &AppState,
    req: &Request,
    body: &cokret_sdk::FederationTransactionRequestBody,
) -> Result<(), AppError> {
    let body_value = serde_json::to_value(body).map_err(|error| {
        AppError::internal(format!(
            "federation transaction body serialization failed: {error}"
        ))
    })?;
    verify_inbound_federation_http_signature(
        state,
        req,
        &body_value,
        body.origin.as_str(),
        body.destination.as_str(),
        "federation_transaction",
    )
}

fn verify_inbound_federation_http_signature(
    state: &AppState,
    req: &Request,
    body_value: &Value,
    body_origin: &str,
    body_destination: &str,
    metric_label: &'static str,
) -> Result<(), AppError> {
    let _timing_bucket = FederationAuthTimingGuard::enter();
    let body_bytes = cokret_sdk::canonical::canonical_json_bytes(body_value).map_err(|error| {
        AppError::new(
            crate::error::ErrorCode::SchemaViolation,
            format!("federation request body is not canonical JSON: {error}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;
    let expected_content_digest = content_digest_header(&body_bytes);
    let expected_request_digest = cokret_sdk::canonical::sha256_digest(&body_bytes);
    validate_federation_request_binding(&state.config.trust_domain, req, &expected_request_digest)?;

    let content_digest = required_header(req, "content-digest")?;
    if content_digest != expected_content_digest {
        crate::metrics::record_digest_mismatch(&format!("{metric_label}_content_digest"));
        return Err(signature_error(
            "Content-Digest does not match federation canonical request body",
        ));
    }
    let request_digest = required_header(req, "request-canonical-digest")?;
    if request_digest != expected_request_digest {
        crate::metrics::record_digest_mismatch(&format!("{metric_label}_request_digest"));
        return Err(signature_error(
            "Request-Canonical-Digest does not match federation canonical request body",
        ));
    }

    let source_service_did = required_header(req, "source-service-did")?;
    let destination_service_did = required_header(req, "destination-service-did")?;
    let source_trust_domain = required_header(req, "source-trust-domain")?;
    let destination_trust_domain = required_header(req, "destination-trust-domain")?;
    if destination_service_did != body_destination
        || destination_service_did != state.config.service_did
    {
        return Err(signature_error(
            "Destination-Service-DID does not match the federation request destination",
        ));
    }
    if destination_trust_domain != state.config.trust_domain {
        return Err(signature_error(
            "Destination-Trust-Domain does not match this service",
        ));
    }
    let expected_source_trust_domain = trust_domain_from_service_did(&source_service_did);
    if source_trust_domain != expected_source_trust_domain {
        return Err(signature_error(
            "Source-Trust-Domain does not match Source-Service-DID",
        ));
    }

    let target_uri = signature_target_uri(req, state);
    let authority = signature_authority(req, state);
    let endpoint_digest =
        validate_destination_authority(state, req, &authority, &destination_service_did)?;
    let method = req.method().as_str().to_ascii_uppercase();
    let outer_params = signature_params(req, "signature-input")?;
    validate_signature_params(&outer_params, &source_service_did, "outer")?;
    let outer_base = federation_http_signature_base(
        &method,
        &target_uri,
        &authority,
        &content_digest,
        &source_service_did,
        &destination_service_did,
        &source_trust_domain,
        &destination_trust_domain,
        &request_digest,
        endpoint_digest.as_deref(),
        &outer_params,
    );
    verify_signature_header(
        state,
        req,
        "signature",
        &source_service_did,
        &outer_base,
        "outer",
    )?;

    if source_service_did != body_origin {
        verify_relay_inner_signature(
            state,
            req,
            &method,
            &target_uri,
            &content_digest,
            body_origin,
            &source_service_did,
            &destination_service_did,
            &request_digest,
        )?;
    }

    Ok(())
}

/// Verify the inbound RFC 9421 HTTP Message Signature for a spec-canonical
/// `/_cokret/peer/*` request and enforce the local peer deny policy.
///
/// Unlike [`verify_inbound_federation_http_signature`] (the private
/// `/_soland/peer/federation/*` track, which carries a typed body with an
/// `origin`/`destination` field and an optional relay-inner signature), the
/// canonical peer surface authenticates purely on the federation trust headers:
/// the origin is the `source-service-did` header, so there is no relay-inner
/// hop to verify. The function handles both bodied requests (POST submit /
/// query_post / resolve / invites / contacts) and bodyless GETs (query /
/// frontier / snapshot.head), binding the signature to an empty-body
/// Content-Digest in the latter case.
pub(in crate::routing) fn verify_inbound_peer_http_signature(
    state: &AppState,
    req: &Request,
    body: Option<&Value>,
) -> Result<(), AppError> {
    let _timing_bucket = FederationAuthTimingGuard::enter();
    let body_digests = match body {
        Some(value) => {
            let body_bytes =
                cokret_sdk::canonical::canonical_json_bytes(value).map_err(|error| {
                    AppError::new(
                        crate::error::ErrorCode::SchemaViolation,
                        format!("peer request body is not canonical JSON: {error}"),
                    )
                    .with_status(StatusCode::BAD_REQUEST)
                })?;
            let expected_content_digest = content_digest_header(&body_bytes);
            let expected_request_digest = cokret_sdk::canonical::sha256_digest(&body_bytes);
            validate_federation_request_binding(
                &state.config.trust_domain,
                req,
                &expected_request_digest,
            )?;
            Some((expected_content_digest, expected_request_digest))
        }
        None => None,
    };

    let (content_digest, request_digest) =
        if let Some((expected_content_digest, expected_request_digest)) = body_digests {
            let content_digest = required_header(req, "content-digest")?;
            if content_digest != expected_content_digest {
                crate::metrics::record_digest_mismatch("peer_request_content_digest");
                return Err(signature_error(
                    "Content-Digest does not match peer canonical request body",
                ));
            }
            let request_digest = required_header(req, "request-canonical-digest")?;
            if request_digest != expected_request_digest {
                crate::metrics::record_digest_mismatch("peer_request_request_digest");
                return Err(signature_error(
                    "Request-Canonical-Digest does not match peer canonical request body",
                ));
            }
            (Some(content_digest), Some(request_digest))
        } else {
            (None, None)
        };

    let source_service_did = required_header(req, "source-service-did")?;
    let destination_service_did = required_header(req, "destination-service-did")?;
    let source_trust_domain = required_header(req, "source-trust-domain")?;
    let destination_trust_domain = required_header(req, "destination-trust-domain")?;

    if destination_service_did != state.config.service_did {
        return Err(signature_error(
            "Destination-Service-DID does not match this service",
        ));
    }
    if destination_trust_domain != state.config.trust_domain {
        return Err(signature_error(
            "Destination-Trust-Domain does not match this service",
        ));
    }
    let expected_source_trust_domain = trust_domain_from_service_did(&source_service_did);
    if source_trust_domain != expected_source_trust_domain {
        return Err(signature_error(
            "Source-Trust-Domain does not match Source-Service-DID",
        ));
    }

    let target_uri = signature_target_uri(req, state);
    let authority = signature_authority(req, state);
    let endpoint_digest =
        validate_destination_authority(state, req, &authority, &destination_service_did)?;
    let method = req.method().as_str().to_ascii_uppercase();
    let outer_params = signature_params(req, "signature-input")?;
    validate_signature_params(&outer_params, &source_service_did, "outer")?;
    let outer_base = peer_http_signature_base(
        &method,
        &target_uri,
        &authority,
        content_digest.as_deref(),
        &source_service_did,
        &destination_service_did,
        &source_trust_domain,
        &destination_trust_domain,
        request_digest.as_deref(),
        endpoint_digest.as_deref(),
        &outer_params,
    );
    verify_signature_header(
        state,
        req,
        "signature",
        &source_service_did,
        &outer_base,
        "outer",
    )?;

    if crate::security::federation_origin_denied(&source_service_did) {
        return Err(signature_error("peer is denied by local federation policy"));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_relay_inner_signature(
    state: &AppState,
    req: &Request,
    method: &str,
    target_uri: &str,
    content_digest: &str,
    origin_service_did: &str,
    relay_service_did: &str,
    destination_service_did: &str,
    request_digest: &str,
) -> Result<(), AppError> {
    let inner_params = signature_params(req, "relay-inner-signature-input")?;
    validate_signature_params(&inner_params, origin_service_did, "relay inner")?;
    let inner_base = format!(
        "\"@method\": {method}\n\
         \"@target-uri\": {target_uri}\n\
         \"content-digest\": {content_digest}\n\
         \"origin-service-did\": {origin_service_did}\n\
         \"relay-service-did\": {relay_service_did}\n\
         \"destination-service-did\": {destination_service_did}\n\
         \"request-canonical-digest\": {request_digest}\n\
         \"@signature-params\": {inner_params}",
    );
    verify_signature_header(
        state,
        req,
        "relay-inner-signature",
        origin_service_did,
        &inner_base,
        "relay inner",
    )
}

#[allow(clippy::too_many_arguments)]
fn federation_http_signature_base(
    method: &str,
    target_uri: &str,
    authority: &str,
    content_digest: &str,
    source_service_did: &str,
    destination_service_did: &str,
    source_trust_domain: &str,
    destination_trust_domain: &str,
    request_digest: &str,
    destination_service_endpoint_digest: Option<&str>,
    signature_params: &str,
) -> String {
    // federation.md §3.2 line 180/185: when a Destination-Service-Endpoint-Digest
    // is present it MUST be a covered component of the signature transcript so the
    // signer commits to the destination endpoint (anti virtual-host confusion on
    // shared ingress). Single-endpoint deployments omit it and the component is
    // simply absent from the base.
    let endpoint_component = destination_service_endpoint_digest
        .map(|digest| format!("\"destination-service-endpoint-digest\": {digest}\n"))
        .unwrap_or_default();
    format!(
        "\"@method\": {method}\n\
         \"@target-uri\": {target_uri}\n\
         \"@authority\": {authority}\n\
         \"content-digest\": {content_digest}\n\
         \"source-service-did\": {source_service_did}\n\
         \"destination-service-did\": {destination_service_did}\n\
         \"source-trust-domain\": {source_trust_domain}\n\
         \"destination-trust-domain\": {destination_trust_domain}\n\
         \"request-canonical-digest\": {request_digest}\n\
         {endpoint_component}\
         \"@signature-params\": {signature_params}",
    )
}

#[allow(clippy::too_many_arguments)]
fn peer_http_signature_base(
    method: &str,
    target_uri: &str,
    authority: &str,
    content_digest: Option<&str>,
    source_service_did: &str,
    destination_service_did: &str,
    source_trust_domain: &str,
    destination_trust_domain: &str,
    request_digest: Option<&str>,
    destination_service_endpoint_digest: Option<&str>,
    signature_params: &str,
) -> String {
    let content_component = content_digest
        .map(|digest| format!("\"content-digest\": {digest}\n"))
        .unwrap_or_default();
    let request_digest_component = request_digest
        .map(|digest| format!("\"request-canonical-digest\": {digest}\n"))
        .unwrap_or_default();
    let endpoint_component = destination_service_endpoint_digest
        .map(|digest| format!("\"destination-service-endpoint-digest\": {digest}\n"))
        .unwrap_or_default();
    format!(
        "\"@method\": {method}\n\
         \"@target-uri\": {target_uri}\n\
         \"@authority\": {authority}\n\
         {content_component}\
         \"source-service-did\": {source_service_did}\n\
         \"destination-service-did\": {destination_service_did}\n\
         \"source-trust-domain\": {source_trust_domain}\n\
         \"destination-trust-domain\": {destination_trust_domain}\n\
         {request_digest_component}\
         {endpoint_component}\
         \"@signature-params\": {signature_params}",
    )
}

/// federation.md §3.2 line 105-106: verify the signed `@authority` host matches
/// the endpoint registered for the Destination-Service-DID. Because the inbound
/// path already enforces `destination_service_did == this service`, the
/// authoritative endpoint is this service's own published `public_base_url`.
///
/// Returns the `Destination-Service-Endpoint-Digest` to bind into the transcript
/// when the request carries that header (required on shared ingress, line 180);
/// when present it MUST equal the sha256 digest of the registered endpoint
/// canonical URL.
fn validate_destination_authority(
    state: &AppState,
    req: &Request,
    authority: &str,
    destination_service_did: &str,
) -> Result<Option<String>, AppError> {
    // The registered endpoint authority for this (destination) service.
    if let Some(expected_authority) = public_base_url_authority(state) {
        if !authority.eq_ignore_ascii_case(&expected_authority) {
            crate::metrics::record_digest_mismatch("federation_authority_mismatch");
            return Err(signature_error(
                "signed @authority host does not match the Destination-Service-DID endpoint",
            ));
        }
    }

    // Optional endpoint-digest binding (conditional-required on shared ingress).
    let observed = req
        .headers()
        .get("destination-service-endpoint-digest")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    if let Some(observed_digest) = observed {
        let expected_digest = cokret_sdk::canonical::sha256_digest(
            state
                .config
                .public_base_url
                .trim_end_matches('/')
                .as_bytes(),
        );
        if observed_digest != expected_digest {
            crate::metrics::record_digest_mismatch("federation_endpoint_digest_mismatch");
            return Err(signature_error(
                "Destination-Service-Endpoint-Digest does not match the registered endpoint",
            ));
        }
        // Sanity: the digest must be for *this* service's destination DID.
        debug_assert_eq!(destination_service_did, state.config.service_did);
        return Ok(Some(observed_digest));
    }
    Ok(None)
}

fn required_header(req: &Request, name: &str) -> Result<String, AppError> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| signature_error(format!("missing required federation header: {name}")))
}

fn signature_params(req: &Request, header_name: &str) -> Result<String, AppError> {
    required_header(req, header_name)?
        .strip_prefix("sig1=")
        .map(ToOwned::to_owned)
        .ok_or_else(|| signature_error(format!("{header_name} must contain sig1 parameters")))
}

pub(super) fn validate_signature_params(
    signature_params: &str,
    expected_service_did: &str,
    label: &str,
) -> Result<(), AppError> {
    let expected_keyid = format!("{expected_service_did}#federation-fanout-key");
    let observed_keyid = signature_param_value(signature_params, "keyid").ok_or_else(|| {
        signature_error(format!(
            "{label} Signature-Input missing keyid; key_rotation_hint=refresh_origin_service_did"
        ))
    })?;
    if observed_keyid != expected_keyid {
        return Err(signature_error(format!(
            "{label} Signature-Input keyid mismatch; key_rotation_hint=refresh_origin_service_did"
        )));
    }
    if signature_param_value(signature_params, "alg").as_deref() != Some("ed25519") {
        return Err(signature_error(format!(
            "{label} Signature-Input alg must be ed25519"
        )));
    }
    let now = Utc::now().timestamp();
    // federation.md §3.2: `created` and `expires` are MUST-present signature
    // parameters; the freshness window is normative and is the only protocol-level
    // replay backstop on the inbound write path (an evicted replay cache MUST NOT
    // allow a byte-for-byte replay that falls outside this window). Fail closed when
    // either is absent or unparsable rather than silently accepting the signature.
    let created = signature_param_value(signature_params, "created")
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| {
            signature_error(format!(
                "{label} Signature-Input missing required `created` parameter"
            ))
        })?;
    let expires = signature_param_value(signature_params, "expires")
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| {
            signature_error(format!(
                "{label} Signature-Input missing required `expires` parameter"
            ))
        })?;
    // `created` MUST be within ±30s of local clock (both directions).
    if (created - now).abs() > 30 {
        return Err(signature_error(format!(
            "{label} signature created timestamp outside ±30s clock-skew window"
        )));
    }
    // Window width MUST NOT exceed 300s.
    if expires < created || expires - created > 300 {
        return Err(signature_error(format!(
            "{label} signature validity window exceeds 300s"
        )));
    }
    // `expires` MUST be in the future relative to local clock.
    if expires < now {
        return Err(signature_error(format!("{label} signature is expired")));
    }
    Ok(())
}

fn signature_param_value(signature_params: &str, key: &str) -> Option<String> {
    signature_params.split(';').skip(1).find_map(|part| {
        let (name, value) = part.split_once('=')?;
        if name.trim() != key {
            return None;
        }
        Some(value.trim().trim_matches('"').to_owned())
    })
}

fn verify_signature_header(
    state: &AppState,
    req: &Request,
    header_name: &str,
    service_did: &str,
    signature_base: &str,
    label: &str,
) -> Result<(), AppError> {
    let signature_header = required_header(req, header_name)?;
    let signature = decode_signature_header(&signature_header).map_err(|message| {
        signature_error(format!(
            "{label} signature decode failed: {message}; key_rotation_hint=refresh_origin_service_did"
        ))
    })?;
    let verifying_key = verifying_key_for_service_did(state, service_did)?;
    verifying_key
        .verify(signature_base.as_bytes(), &signature)
        .map_err(|_| {
            signature_error(format!(
                "{label} signature verification failed; key_rotation_hint=refresh_origin_service_did"
            ))
        })
}

pub(super) fn origin_key_state_digest_for_service(
    state: &AppState,
    service_did: &str,
) -> Result<String, AppError> {
    let verifying_key = verifying_key_for_service_did(state, service_did)?;
    let mut hasher = Sha256::new();
    hasher.update(b"soland:federation-origin-key-state:v1:");
    hasher.update(service_did.as_bytes());
    hasher.update(verifying_key.to_bytes());
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn decode_signature_header(value: &str) -> Result<Signature, &'static str> {
    let signature_b64 = value
        .strip_prefix("sig1=:")
        .and_then(|value| value.strip_suffix(':'))
        .ok_or("Signature header must use sig1=:base64: form")?;
    let signature_bytes = STANDARD
        .decode(signature_b64)
        .map_err(|_| "Signature header base64 is invalid")?;
    Signature::from_slice(&signature_bytes).map_err(|_| "Signature header is not Ed25519 length")
}

fn verifying_key_for_service_did(
    state: &AppState,
    service_did: &str,
) -> Result<VerifyingKey, AppError> {
    if service_did == state.config.service_did {
        return Ok(state.notary_signing_key().verifying_key());
    }
    if let Some(key) = configured_peer_verifying_key(service_did)? {
        return Ok(key);
    }
    if state.config.development_mode {
        tracing::warn!(
            service_did,
            "development_mode accepted deterministic federation service key fallback"
        );
        return Ok(development_service_signing_key(service_did).verifying_key());
    }
    let verification_method = format!("{service_did}#federation-fanout-key");
    if let Ok(key) = crate::jws_verify::resolve_ed25519_pubkey(state, &verification_method) {
        return Ok(key);
    }
    Err(signature_error(
        "source service key unavailable; key_rotation_hint=refresh_origin_service_did",
    ))
}

fn configured_peer_verifying_key(service_did: &str) -> Result<Option<VerifyingKey>, AppError> {
    let Ok(raw) = std::env::var("SOLAND_FEDERATION_PEER_PUBLIC_KEYS") else {
        return Ok(None);
    };
    let expected_method = format!("{service_did}#federation-fanout-key");
    for entry in raw.split([',', ';', '\n']) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((id, material)) = entry
            .split_once('=')
            .or_else(|| entry.split_once(':'))
            .map(|(id, material)| (id.trim(), material.trim()))
        else {
            continue;
        };
        if id != service_did && id != expected_method {
            continue;
        }
        return decode_peer_verifying_key(material)
            .map(Some)
            .map_err(|message| signature_error(format!("peer public key invalid: {message}")));
    }
    Ok(None)
}

fn decode_peer_verifying_key(material: &str) -> Result<VerifyingKey, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(material.as_bytes())
        .or_else(|_| STANDARD.decode(material.as_bytes()))
        .map_err(|error| format!("public key is not base64/base64url: {error}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "Ed25519 public key must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&raw).map_err(|error| format!("invalid Ed25519 key: {error}"))
}

fn development_service_signing_key(service_did: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"soland:notary-ephemeral:");
    hasher.update(service_did.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

pub(in crate::routing) fn signature_target_uri(req: &Request, state: &AppState) -> String {
    let scheme = req
        .uri()
        .scheme_str()
        .map(ToOwned::to_owned)
        .or_else(|| public_base_url_scheme(state))
        .unwrap_or_else(|| "http".to_owned());
    let authority = signature_authority(req, state);
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| req.uri().path());
    format!("{scheme}://{authority}{path_and_query}")
}

pub(in crate::routing) fn signature_authority(req: &Request, state: &AppState) -> String {
    // Behind a deployment gateway the upstream `Host` may be rewritten to the
    // internal origin, so prefer the client-visible `X-Forwarded-Host` (first
    // hop) the gateway records — matching how the peer / client signed the
    // `@authority` (and the DPoP `htu`, see `auth_grant_dpop::request_authority`).
    // Falls back to the request authority / `Host` / configured public origin for
    // a same-origin deployment with no proxy in front.
    forwarded_host_authority(req)
        .or_else(|| {
            req.uri()
                .authority()
                .map(|authority| authority.as_str().to_owned())
        })
        .or_else(|| {
            req.headers()
                .get("host")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned)
        })
        .or_else(|| public_base_url_authority(state))
        .unwrap_or_else(|| "server".to_owned())
}

/// Client-visible authority from `X-Forwarded-Host` (first hop), set by the
/// deployment gateway when it rewrites the upstream `Host`. Absent / empty →
/// `None` so the caller falls back to the request authority / `Host`.
fn forwarded_host_authority(req: &Request) -> Option<String> {
    req.headers()
        .get("x-forwarded-host")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(',').next().unwrap_or(value).trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn public_base_url_scheme(state: &AppState) -> Option<String> {
    reqwest::Url::parse(&state.config.public_base_url)
        .ok()
        .map(|url| url.scheme().to_owned())
}

fn public_base_url_authority(state: &AppState) -> Option<String> {
    let url = reqwest::Url::parse(&state.config.public_base_url).ok()?;
    let host = url.host_str()?;
    Some(
        url.port()
            .map(|port| format!("{host}:{port}"))
            .unwrap_or_else(|| host.to_owned()),
    )
}

pub(crate) fn trust_domain_from_service_did(service_did: &str) -> String {
    let scope = did_host_from_service_did(service_did).unwrap_or_else(|| {
        service_did
            .strip_prefix("did:key:")
            .unwrap_or(service_did)
            .to_ascii_lowercase()
            .replace(':', ".")
    });
    format!("ck:trust_domain:{scope}")
}

fn did_host_from_service_did(service_did: &str) -> Option<String> {
    let host = if let Some(rest) = service_did.strip_prefix("did:web:") {
        rest.split(':').next()?
    } else if let Some(rest) = service_did.strip_prefix("did:webvh:") {
        let mut parts = rest.split(':');
        let scid = parts.next()?;
        let host = parts.next()?;
        if scid.is_empty() {
            return None;
        }
        host
    } else {
        return None;
    };
    let host = host
        .split("%3A")
        .next()
        .unwrap_or(host)
        .split("%3a")
        .next()
        .unwrap_or(host)
        .trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn signature_error(message: impl Into<String>) -> AppError {
    let detail = message.into();
    tracing::warn!(
        federation_auth_detail = %detail,
        "federation request authentication failed"
    );
    normalize_federation_auth_failure_delay();
    AppError::unauthenticated(FEDERATION_AUTH_FAILURE_MESSAGE)
}

fn cross_domain_replay_error(message: impl Into<String>) -> AppError {
    let detail = message.into();
    tracing::warn!(
        federation_auth_detail = %detail,
        "federation cross-domain replay check failed"
    );
    normalize_federation_auth_failure_delay();
    AppError::unauthenticated(FEDERATION_AUTH_FAILURE_MESSAGE)
}

fn normalize_federation_auth_failure_delay() {
    let started_at =
        FEDERATION_AUTH_TIMING_STARTED_AT.with(|started_at| started_at.borrow().clone());
    let remaining = started_at
        .and_then(|started_at| {
            FEDERATION_AUTH_FAILURE_TIMING_BUCKET.checked_sub(started_at.elapsed())
        })
        .unwrap_or(FEDERATION_AUTH_FAILURE_TIMING_BUCKET);
    if remaining.as_nanos() > 0 {
        std::thread::sleep(remaining);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_domain_derives_webvh_host_not_scid() {
        assert_eq!(
            trust_domain_from_service_did(
                "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:local.host:webvh:service"
            ),
            "ck:trust_domain:local.host"
        );
    }

    #[test]
    fn federation_auth_errors_share_public_message() {
        assert_eq!(
            signature_error("missing required federation header: signature").message,
            FEDERATION_AUTH_FAILURE_MESSAGE
        );
        assert_eq!(
            cross_domain_replay_error("Destination-Trust-Domain mismatch").message,
            FEDERATION_AUTH_FAILURE_MESSAGE
        );
    }

    #[test]
    fn federation_auth_errors_use_timing_bucket() {
        let started_at = Instant::now();
        let _ = signature_error("fast auth failure");
        assert!(started_at.elapsed() >= FEDERATION_AUTH_FAILURE_TIMING_BUCKET);
    }
}
