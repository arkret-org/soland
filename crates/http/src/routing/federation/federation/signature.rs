use std::time::{Duration as StdDuration, Instant};

use ed25519_dalek::{SigningKey, VerifyingKey};
use salvo::http::StatusCode;
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::http_signature::{self, SignatureBaseComponent, SignatureWindowViolation};

use super::wire::FederationTrustHeaders;
use crate::state::AppState;

pub(super) const FEDERATION_AUTH_FAILURE_MESSAGE: &str = "federation request authentication failed";
const FEDERATION_AUTH_FAILURE_TIMING_BUCKET: StdDuration = StdDuration::from_millis(80);

/// Pad a failed federation/peer auth attempt that started at `started_at` up to
/// the constant [`FEDERATION_AUTH_FAILURE_TIMING_BUCKET`] (federation.md §3.2 /
/// §8.3 timing-bucket normalization), waiting via `tokio::time::sleep().await`
/// so the pad never blocks a tokio worker thread.
///
/// Previously this used a thread-local timing guard plus `std::thread::sleep`,
/// which pinned a worker for the full 80ms bucket on every failure — letting an
/// unauthenticated peer exhaust the runtime thread pool. The start instant is
/// now a plain local captured at verify entry and the sleep is async, so there
/// is no thread-local-across-`.await` hazard and no worker blocking.
async fn apply_federation_auth_failure_delay(started_at: Instant) {
    let remaining = FEDERATION_AUTH_FAILURE_TIMING_BUCKET
        .checked_sub(started_at.elapsed())
        .unwrap_or(FEDERATION_AUTH_FAILURE_TIMING_BUCKET);
    if remaining.as_nanos() > 0 {
        tokio::time::sleep(remaining).await;
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
    let expected_destination = arkret_identifiers::TypedTrustDomainId::new(trust_domain.to_owned())
        .map_err(|error| AppError::internal(format!("configured trust_domain invalid: {error}")))?;
    validate_federation_headers(&headers, &expected_destination, request_hash)
}

pub(super) fn validate_federation_headers(
    headers: &FederationTrustHeaders,
    expected_destination: &arkret_identifiers::TypedTrustDomainId,
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

/// Verify the inbound RFC 9421 HTTP Message Signature for a spec-canonical
/// `/_arkret/peer/*` request and enforce the local peer deny policy.
///
/// The canonical peer surface authenticates purely on the federation trust headers:
/// the origin is the `source-service-id` header, so there is no relay-inner
/// hop to verify. The function handles both bodied requests (POST submit /
/// query_post / resolve / invites / contacts) and bodyless GETs (query /
/// frontier / snapshot.head), binding the signature to an empty-body
/// Content-Digest in the latter case.
pub(in crate::routing) async fn verify_inbound_peer_http_signature(
    state: &AppState,
    req: &mut Request,
    has_body: bool,
) -> Result<(), AppError> {
    if has_body {
        http_signature::reject_content_encoding(req, || {
            AppError::new(
                soland_http::error::ErrorCode::SchemaViolation,
                "peer signed JSON requests must not use Content-Encoding",
            )
            .with_status(StatusCode::BAD_REQUEST)
        })?;
    }
    let body_bytes = match has_body {
        true => Some(
            req.payload()
                .await
                .map_err(|error| {
                    AppError::bad_json(format!("unable to read peer request body: {error}"))
                })?
                .to_vec(),
        ),
        false => None,
    };
    // Bucket-normalize the failure timing without blocking a tokio worker:
    // run the synchronous verify body, then async-pad on the error path.
    let started_at = Instant::now();
    let outcome = verify_inbound_peer_http_signature_inner(state, req, body_bytes.as_deref());
    if outcome.is_err() {
        apply_federation_auth_failure_delay(started_at).await;
    }
    outcome
}

fn verify_inbound_peer_http_signature_inner(
    state: &AppState,
    req: &Request,
    body_bytes: Option<&[u8]>,
) -> Result<(), AppError> {
    let body_digests = match body_bytes {
        Some(bytes) => {
            let body_digests = http_signature::exact_body_digests(bytes);
            validate_federation_request_binding(
                &state.config().trust_domain,
                req,
                &body_digests.request_digest,
            )?;
            Some(body_digests)
        }
        None => None,
    };

    let (content_digest, request_digest) = if let Some(expected) = body_digests {
        let content_digest = required_header(req, "content-digest")?;
        if content_digest != expected.content_digest {
            crate::metrics::record_digest_mismatch("peer_request_content_digest");
            return Err(signature_error(
                "Content-Digest does not match peer canonical request body",
            ));
        }
        let request_digest = required_header(req, "request-canonical-digest")?;
        if request_digest != expected.request_digest {
            crate::metrics::record_digest_mismatch("peer_request_request_digest");
            return Err(signature_error(
                "Request-Canonical-Digest does not match peer canonical request body",
            ));
        }
        http_signature::validate_canonical_json_body(
            body_bytes.expect("body digests exist only for bodied requests"),
            |error| {
                AppError::new(
                    soland_http::error::ErrorCode::SchemaViolation,
                    format!("peer request body is not canonical JSON: {error}"),
                )
                .with_status(StatusCode::BAD_REQUEST)
            },
        )?;
        (Some(content_digest), Some(request_digest))
    } else {
        (None, None)
    };

    let source_service_id = required_header(req, "source-service-id")?;
    let destination_service_id = required_header(req, "destination-service-id")?;
    let source_trust_domain = required_header(req, "source-trust-domain")?;
    let destination_trust_domain = required_header(req, "destination-trust-domain")?;

    if destination_service_id != *state.service_id() {
        return Err(signature_error(
            "Destination-Service-ID does not match this service",
        ));
    }
    if destination_trust_domain != state.config().trust_domain {
        return Err(signature_error(
            "Destination-Trust-Domain does not match this service",
        ));
    }
    // Keep the asserted source domain in the signature transcript. A service
    // DID may legitimately describe a separately named deployment domain, so
    // deriving and comparing a domain from the DID would reject valid peers.
    let target_uri = signature_target_uri(req, state);
    let authority = signature_authority(req, state);
    let endpoint_digest =
        validate_destination_authority(state, req, &authority, &destination_service_id)?;
    let method = req.method().as_str().to_owned();
    let outer_params = signature_params(req, "signature-input")?;
    validate_signature_params(&outer_params, &source_service_id, "outer")?;
    let idempotency_key = req
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let outer_base = peer_http_signature_base(
        &method,
        &target_uri,
        &authority,
        content_digest.as_deref(),
        &source_service_id,
        &destination_service_id,
        &source_trust_domain,
        &destination_trust_domain,
        request_digest.as_deref(),
        idempotency_key,
        endpoint_digest.as_deref(),
        &outer_params,
    );
    verify_signature_header(
        state,
        req,
        "signature",
        &source_service_id,
        &outer_base,
        "outer",
    )?;
    let source_verifying_key = verifying_key_for_service_id(state, &source_service_id)?;
    let source_verification_method =
        crate::routing::federation::federation_service_signature_key_id(&source_service_id);
    state.install_federation_peer_verifying_key(None, &source_service_id, source_verifying_key);
    state.install_federation_peer_verification_method_key(
        None,
        &source_verification_method,
        source_verifying_key,
    );

    if crate::security::federation_origin_denied(&source_service_id) {
        return Err(signature_error("peer is denied by local federation policy"));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn peer_http_signature_base(
    method: &str,
    target_uri: &str,
    authority: &str,
    content_digest: Option<&str>,
    source_service_id: &str,
    destination_service_id: &str,
    source_trust_domain: &str,
    destination_trust_domain: &str,
    request_digest: Option<&str>,
    idempotency_key: Option<&str>,
    destination_service_endpoint_digest: Option<&str>,
    signature_params: &str,
) -> String {
    http_signature::signature_base(
        &[
            SignatureBaseComponent::required("@method", method),
            SignatureBaseComponent::required("@target-uri", target_uri),
            SignatureBaseComponent::required("@authority", authority),
            SignatureBaseComponent::optional("content-digest", content_digest),
            SignatureBaseComponent::required("source-service-id", source_service_id),
            SignatureBaseComponent::required("destination-service-id", destination_service_id),
            SignatureBaseComponent::required("source-trust-domain", source_trust_domain),
            SignatureBaseComponent::required("destination-trust-domain", destination_trust_domain),
            SignatureBaseComponent::optional("request-canonical-digest", request_digest),
            SignatureBaseComponent::optional("idempotency-key", idempotency_key),
            SignatureBaseComponent::optional(
                "destination-service-endpoint-digest",
                destination_service_endpoint_digest,
            ),
        ],
        signature_params,
    )
}

/// federation.md §3.2 line 105-106: verify the signed `@authority` host matches
/// the endpoint registered for the Destination-Service-ID. Because the inbound
/// path already enforces `destination_service_id == this service`, the
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
    destination_service_id: &str,
) -> Result<Option<String>, AppError> {
    // The registered endpoint authority for this (destination) service.
    if let Some(expected_authority) = public_base_url_authority(state)
        && !authority.eq_ignore_ascii_case(&expected_authority)
    {
        crate::metrics::record_digest_mismatch("federation_authority_mismatch");
        return Err(signature_error(
            "signed @authority host does not match the Destination-Service-ID endpoint",
        ));
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
        let expected_digest = arkret_canonical::sha256_digest(
            state
                .config()
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
        debug_assert_eq!(destination_service_id, state.service_id());
        return Ok(Some(observed_digest));
    }
    Ok(None)
}

fn required_header(req: &Request, name: &str) -> Result<String, AppError> {
    http_signature::required_header(req, name, |name| {
        signature_error(format!("missing required federation header: {name}"))
    })
}

fn signature_params(req: &Request, header_name: &str) -> Result<String, AppError> {
    http_signature::signature_params(
        req,
        header_name,
        || signature_error(format!("missing required federation header: {header_name}")),
        || signature_error(format!("{header_name} must contain sig1 parameters")),
    )
}

pub(super) fn validate_signature_params(
    signature_params: &str,
    expected_service_id: &str,
    label: &str,
) -> Result<(), AppError> {
    let expected_keyid =
        crate::routing::federation::federation_service_signature_key_id(expected_service_id);
    let observed_keyid = http_signature::signature_param_value(signature_params, "keyid")
        .ok_or_else(|| {
            signature_error(format!(
                "{label} Signature-Input missing keyid; key_rotation_hint=refresh_origin_service_id"
            ))
        })?;
    if observed_keyid != expected_keyid {
        return Err(signature_error(format!(
            "{label} Signature-Input keyid mismatch; key_rotation_hint=refresh_origin_service_id"
        )));
    }
    if http_signature::signature_param_value(signature_params, "alg").as_deref() != Some("ed25519")
    {
        return Err(signature_error(format!(
            "{label} Signature-Input alg must be ed25519"
        )));
    }
    http_signature::validate_signature_freshness(signature_params).map_err(|violation| {
        let message = match violation {
            SignatureWindowViolation::MissingCreated => {
                format!("{label} Signature-Input missing required `created` parameter")
            }
            SignatureWindowViolation::MissingExpires => {
                format!("{label} Signature-Input missing required `expires` parameter")
            }
            SignatureWindowViolation::CreatedOutsideSkew => {
                format!("{label} signature created timestamp outside ±30s clock-skew window")
            }
            SignatureWindowViolation::InvalidValidityWindow => {
                format!("{label} signature validity window exceeds 300s")
            }
            SignatureWindowViolation::Expired => format!("{label} signature is expired"),
        };
        signature_error(message)
    })
}

fn verify_signature_header(
    state: &AppState,
    req: &Request,
    header_name: &str,
    service_id: &str,
    signature_base: &str,
    label: &str,
) -> Result<(), AppError> {
    http_signature::verify_signature_header(
        req,
        header_name,
        signature_base,
        |name| signature_error(format!("missing required federation header: {name}")),
        |message| {
            signature_error(format!(
                "{label} signature decode failed: {message}; key_rotation_hint=refresh_origin_service_id"
            ))
        },
        || {
            signature_error(format!(
                "{label} signature verification failed; key_rotation_hint=refresh_origin_service_id"
            ))
        },
        || verifying_key_for_service_id(state, service_id),
    )
}

fn verifying_key_for_service_id(
    state: &AppState,
    service_id: &str,
) -> Result<VerifyingKey, AppError> {
    if service_id == state.service_id() {
        return Ok(state.notary_signing_key().verifying_key());
    }
    if let Some(key) = state.federation_peer_verifying_key(service_id) {
        return Ok(key);
    }
    // did:key is self-resolving and binds its verification key directly in
    // the identifier. Never replace that authoritative key with the
    // development deterministic fallback: a peer using a durable notary key
    // would otherwise sign correctly and still fail verification in dev mode.
    if service_id.starts_with("did:key:") {
        let verification_method =
            crate::routing::federation::federation_service_signature_key_id(service_id);
        return crate::jws_verify::resolve_ed25519_pubkey(state, &verification_method).map_err(
            |_| {
                signature_error(
                    "source did:key service key unavailable; key_rotation_hint=refresh_origin_service_id",
                )
            },
        );
    }
    if state.config().development_mode {
        tracing::warn!(
            service_id,
            "development_mode accepted deterministic federation service key fallback"
        );
        return Ok(development_service_signing_key(service_id).verifying_key());
    }
    let verification_method =
        crate::routing::federation::federation_service_signature_key_id(service_id);
    if let Ok(key) = crate::jws_verify::resolve_ed25519_pubkey(state, &verification_method) {
        return Ok(key);
    }
    Err(signature_error(
        "source service key unavailable; key_rotation_hint=refresh_origin_service_id",
    ))
}

fn development_service_signing_key(service_id: &str) -> SigningKey {
    http_signature::deterministic_development_signing_key(b"soland:notary-ephemeral:", service_id)
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
    reqwest::Url::parse(&state.config().public_base_url)
        .ok()
        .map(|url| url.scheme().to_owned())
}

fn public_base_url_authority(state: &AppState) -> Option<String> {
    let url = reqwest::Url::parse(&state.config().public_base_url).ok()?;
    let host = url.host_str()?;
    Some(
        url.port()
            .map(|port| format!("{host}:{port}"))
            .unwrap_or_else(|| host.to_owned()),
    )
}

pub(crate) fn trust_domain_from_service_id(service_id: &str) -> String {
    // Single canonical host parser lives in `crate::config`; delegate rather
    // than keep a second (previously casing-drifted) copy.
    let scope = crate::config::did_host_from_service_id(service_id).unwrap_or_else(|| {
        service_id
            .strip_prefix("did:key:")
            .unwrap_or(service_id)
            .to_ascii_lowercase()
            .replace(':', ".")
    });
    format!("ak:trust_domain:{scope}")
}

fn signature_error(message: impl Into<String>) -> AppError {
    let detail = message.into();
    tracing::warn!(
        federation_auth_detail = %detail,
        "federation request authentication failed"
    );
    AppError::unauthenticated(FEDERATION_AUTH_FAILURE_MESSAGE)
}

fn cross_domain_replay_error(message: impl Into<String>) -> AppError {
    let detail = message.into();
    tracing::warn!(
        federation_auth_detail = %detail,
        "federation cross-domain replay check failed"
    );
    AppError::unauthenticated(FEDERATION_AUTH_FAILURE_MESSAGE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_domain_derives_webvh_host_not_scid() {
        assert_eq!(
            trust_domain_from_service_id(
                "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:local.host:webvh:service"
            ),
            "ak:trust_domain:local.host"
        );
    }

    #[test]
    fn federation_auth_errors_share_public_message() {
        assert_eq!(
            signature_error("missing required federation header: signature")
                .message
                .as_ref(),
            FEDERATION_AUTH_FAILURE_MESSAGE
        );
        assert_eq!(
            cross_domain_replay_error("Destination-Trust-Domain mismatch")
                .message
                .as_ref(),
            FEDERATION_AUTH_FAILURE_MESSAGE
        );
    }

    /// The failure-timing pad is now applied via `tokio::time::sleep().await`
    /// (non-blocking) rather than `std::thread::sleep`, so a fast auth failure
    /// is still padded up to the constant bucket but without pinning a worker.
    #[tokio::test(start_paused = true)]
    async fn federation_auth_failure_delay_pads_to_bucket() {
        // The pad is `tokio::time::sleep(remaining).await`. Under
        // `start_paused`, tokio auto-advances its *virtual* clock to satisfy the
        // sleep, so we measure with `tokio::time::Instant` (which tracks the
        // virtual clock) rather than `std::time::Instant` (wall-clock, which the
        // paused runtime does not advance). `started_at` is a `std`-clock value
        // captured immediately before the call, so its `elapsed()` is ~0 and the
        // function pads by the full bucket.
        let virtual_start = tokio::time::Instant::now();
        let started_at = Instant::now();
        apply_federation_auth_failure_delay(started_at).await;
        assert!(virtual_start.elapsed() >= FEDERATION_AUTH_FAILURE_TIMING_BUCKET);
    }
}
