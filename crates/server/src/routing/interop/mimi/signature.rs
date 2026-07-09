use super::*;

pub(super) fn verify_mimi_write_service_proof(
    state: &AppState,
    req: &Request,
    body: &Value,
    room_uri: Option<&str>,
) -> Result<(), AppError> {
    let signature_present =
        req.headers().get("signature").is_some() && req.headers().get("signature-input").is_some();
    if !signature_present {
        return Err(mimi_signature_error_required(
            "MIMI writes require RFC 9421 Signature and Signature-Input headers",
        ));
    }

    let body_digests = http_signature::canonical_body_digests(body, |error| {
        AppError::invalid_param(format!("MIMI request body is not canonical JSON: {error}"))
    })?;
    let expected_content_digest = body_digests.content_digest;
    let content_digest = mimi_required_header(req, "content-digest")?;
    if content_digest != expected_content_digest {
        return Err(mimi_signature_error_invalid(
            "Content-Digest does not cover the canonical MIMI request body",
        ));
    }
    let expected_request_digest = body_digests.request_digest;
    let request_digest = mimi_required_header(req, "request-canonical-digest")?;
    if request_digest != expected_request_digest {
        return Err(mimi_signature_error_invalid(
            "Request-Canonical-Digest does not match the canonical MIMI request body",
        ));
    }

    let source_service_did = mimi_required_header(req, "source-service-did")?;
    if !source_service_did.starts_with("did:") {
        return Err(mimi_signature_error_invalid(
            "Source-Service-DID must be a DID",
        ));
    }
    let destination_service_did = mimi_required_header(req, "destination-service-did")?;
    if destination_service_did != state.config.service_did {
        return Err(mimi_signature_error_invalid(
            "Destination-Service-DID does not match this service",
        ));
    }
    let provider_id = mimi_required_header(req, "provider-id")?;
    if !provider_id.starts_with("mimi://") {
        return Err(mimi_signature_error_invalid(
            "Provider-ID must be a MIMI provider URI",
        ));
    }
    let signed_room_uri = match room_uri {
        Some(expected) => {
            let observed = mimi_required_header(req, "mimi-room-uri")?;
            if observed != expected {
                return Err(mimi_signature_error_invalid(
                    "MIMI-Room-URI does not match the addressed room",
                ));
            }
            Some(observed)
        }
        None => None,
    };

    let signature_params = mimi_signature_params(req)?;
    let verification_method =
        mimi_validate_signature_params(&signature_params, &source_service_did, room_uri.is_some())?;
    let method = req.method().as_str().to_ascii_uppercase();
    let target_uri = crate::routing::federation::signature_target_uri(req, state);
    let authority = crate::routing::federation::signature_authority(req, state);
    let signature_base = mimi_http_signature_base(
        &method,
        &target_uri,
        &authority,
        &content_digest,
        &request_digest,
        &source_service_did,
        &destination_service_did,
        &provider_id,
        signed_room_uri.as_deref(),
        &signature_params,
    );
    mimi_verify_signature_header(state, req, &verification_method, &signature_base)
}

pub(super) fn mimi_required_header(req: &Request, name: &str) -> Result<String, AppError> {
    http_signature::required_header(req, name, |name| {
        mimi_signature_error_invalid(format!("missing required MIMI signature header: {name}"))
    })
}

pub(super) fn mimi_signature_params(req: &Request) -> Result<String, AppError> {
    http_signature::signature_params(
        req,
        "signature-input",
        || mimi_signature_error_required("missing Signature-Input header"),
        || mimi_signature_error_invalid("Signature-Input must carry sig1 parameters"),
    )
}

pub(super) fn mimi_signature_param_value(signature_params: &str, key: &str) -> Option<String> {
    http_signature::signature_param_value(signature_params, key)
}

pub(super) fn mimi_validate_signature_params(
    signature_params: &str,
    source_service_did: &str,
    room_scoped: bool,
) -> Result<String, AppError> {
    for component in [
        "@method",
        "@target-uri",
        "@authority",
        "content-digest",
        "request-canonical-digest",
        "source-service-did",
        "destination-service-did",
        "provider-id",
    ] {
        let needle = format!("\"{component}\"");
        if !signature_params.contains(&needle) {
            return Err(mimi_signature_error_invalid(format!(
                "Signature-Input missing required MIMI component {component}"
            )));
        }
    }
    if room_scoped && !signature_params.contains("\"mimi-room-uri\"") {
        return Err(mimi_signature_error_invalid(
            "Signature-Input missing required MIMI component mimi-room-uri",
        ));
    }

    let verification_method = mimi_signature_param_value(signature_params, "keyid")
        .ok_or_else(|| mimi_signature_error_invalid("Signature-Input missing keyid"))?;
    let expected_prefix = format!("{source_service_did}#");
    if !verification_method.starts_with(&expected_prefix) {
        return Err(mimi_signature_error_invalid(
            "Signature-Input keyid must be controlled by Source-Service-DID",
        ));
    }
    if mimi_signature_param_value(signature_params, "alg").as_deref() != Some("ed25519") {
        return Err(mimi_signature_error_invalid(
            "Signature-Input alg must be ed25519",
        ));
    }

    http_signature::validate_signature_freshness(signature_params).map_err(|violation| {
        let message = match violation {
            SignatureWindowViolation::MissingCreated => {
                "Signature-Input missing required `created` parameter"
            }
            SignatureWindowViolation::MissingExpires => {
                "Signature-Input missing required `expires` parameter"
            }
            SignatureWindowViolation::CreatedOutsideSkew => {
                "signature created timestamp outside +/-30s clock-skew window"
            }
            SignatureWindowViolation::InvalidValidityWindow => {
                "signature validity window exceeds 300s"
            }
            SignatureWindowViolation::Expired => "signature is expired",
        };
        mimi_signature_error_window(message)
    })?;
    Ok(verification_method)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn mimi_http_signature_base(
    method: &str,
    target_uri: &str,
    authority: &str,
    content_digest: &str,
    request_digest: &str,
    source_service_did: &str,
    destination_service_did: &str,
    provider_id: &str,
    room_uri: Option<&str>,
    signature_params: &str,
) -> String {
    http_signature::signature_base(
        &[
            SignatureBaseComponent::required("@method", method),
            SignatureBaseComponent::required("@target-uri", target_uri),
            SignatureBaseComponent::required("@authority", authority),
            SignatureBaseComponent::required("content-digest", content_digest),
            SignatureBaseComponent::required("request-canonical-digest", request_digest),
            SignatureBaseComponent::required("source-service-did", source_service_did),
            SignatureBaseComponent::required("destination-service-did", destination_service_did),
            SignatureBaseComponent::required("provider-id", provider_id),
            SignatureBaseComponent::optional("mimi-room-uri", room_uri),
        ],
        signature_params,
    )
}

pub(super) fn mimi_verify_signature_header(
    state: &AppState,
    req: &Request,
    verification_method: &str,
    signature_base: &str,
) -> Result<(), AppError> {
    http_signature::verify_signature_header(
        req,
        "signature",
        signature_base,
        |name| {
            mimi_signature_error_invalid(format!("missing required MIMI signature header: {name}"))
        },
        |message| mimi_signature_error_invalid(format!("signature decode: {message}")),
        || mimi_signature_error_invalid("signature verification failed"),
        || mimi_resolve_verifying_key(state, verification_method),
    )
}

pub(super) fn mimi_resolve_verifying_key(
    state: &AppState,
    verification_method: &str,
) -> Result<ed25519_dalek::VerifyingKey, AppError> {
    if let Ok(key) = crate::jws_verify::resolve_ed25519_pubkey(state, verification_method) {
        return Ok(key);
    }
    if state.config.development_mode {
        let signing = http_signature::deterministic_development_signing_key(
            b"soland:mimi-provider-key:",
            verification_method,
        );
        return Ok(signing.verifying_key());
    }
    Err(mimi_signature_error_invalid(
        "MIMI provider verification key is unavailable",
    ))
}

pub(super) fn mimi_signature_error_required(message: impl Into<String>) -> AppError {
    AppError::unauthenticated(message)
        .with_status(StatusCode::UNAUTHORIZED)
        .with_top_level_reason("http_signature_required")
}

pub(super) fn mimi_signature_error_invalid(message: impl Into<String>) -> AppError {
    AppError::unauthenticated(message)
        .with_status(StatusCode::UNAUTHORIZED)
        .with_top_level_reason("http_signature_invalid")
}

pub(super) fn mimi_signature_error_window(message: impl Into<String>) -> AppError {
    AppError::unauthenticated(message)
        .with_status(StatusCode::UNAUTHORIZED)
        .with_top_level_reason("signature_window_invalid")
}
