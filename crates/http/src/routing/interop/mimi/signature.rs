use super::*;

pub(super) async fn verify_mimi_write_service_proof(
    state: &AppState,
    req: &mut Request,
    room_uri: Option<&str>,
) -> Result<String, AppError> {
    let signature_present =
        req.headers().get("signature").is_some() && req.headers().get("signature-input").is_some();
    if !signature_present {
        return Err(mimi_signature_error_required(
            "MIMI writes require RFC 9421 Signature and Signature-Input headers",
        ));
    }

    let body_bytes = req
        .payload()
        .await
        .map_err(|error| AppError::bad_json(format!("unable to read MIMI request body: {error}")))?
        .to_vec();
    let source_service_id = mimi_required_header(req, "source-service-id")?;
    let source_service_id = arkret_wire::DidCoreId::new(source_service_id)
        .map_err(|_| mimi_signature_error_invalid("Source-Service-ID must be a core id"))?;
    let destination_service_id = mimi_required_header(req, "destination-service-id")?;
    if destination_service_id != state.service_id().as_str() {
        return Err(mimi_signature_error_invalid(
            "Destination-Service-ID does not match this service",
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

    let signature_input =
        http_signature::parse_signature_input_header(req).map_err(mimi_verification_error)?;
    let verification_method = mimi_validate_signature_input(&signature_input, &source_service_id)?;
    let target_uri = crate::routing::federation::signature_target_uri(req, state);
    let authority = crate::routing::federation::signature_authority(req, state);
    let mut required_components = vec![
        Component::Method,
        Component::TargetUri,
        Component::Authority,
        Component::Header("content-digest".to_owned()),
        Component::Header("source-service-id".to_owned()),
        Component::Header("destination-service-id".to_owned()),
        Component::Header("provider-id".to_owned()),
    ];
    if signed_room_uri.is_some() {
        required_components.push(Component::Header("mimi-room-uri".to_owned()));
    }
    let policy = SignatureVerificationPolicy::new(required_components);
    let verifying_key = mimi_resolve_verifying_key(state, &verification_method)?;
    http_signature::verify_signed_canonical_json_request(
        req,
        &target_uri,
        &authority,
        &body_bytes,
        &verifying_key,
        &policy,
    )
    .map_err(mimi_verification_error)?;
    Ok(source_service_id.to_string())
}

pub(super) fn mimi_required_header(req: &Request, name: &str) -> Result<String, AppError> {
    http_signature::required_header(req, name, |name| {
        mimi_signature_error_invalid(format!("missing required MIMI signature header: {name}"))
    })
}

pub(super) fn mimi_validate_signature_input(
    signature_input: &SignatureInput,
    source_service_id: &arkret_wire::DidCoreId,
) -> Result<String, AppError> {
    if signature_input.label != "sig1" {
        return Err(mimi_signature_error_invalid(
            "Signature-Input must use the sig1 label",
        ));
    }
    let verification_method = signature_input.key_id.clone();
    let controller = verification_method
        .split_once('?')
        .map_or(verification_method.as_str(), |(head, _)| head)
        .split_once('#')
        .map_or(verification_method.as_str(), |(head, _)| head);
    let controller_matches = arkret_wire::DidFullId::new(controller.to_owned())
        .ok()
        .and_then(|full_id| arkret_wire::project_full_id_to_core_id(&full_id).ok())
        .as_ref()
        == Some(source_service_id);
    if !controller_matches {
        return Err(mimi_signature_error_invalid(
            "Signature-Input keyid controller must project to Source-Service-ID",
        ));
    }
    Ok(verification_method)
}

fn mimi_verification_error(error: HttpMessageVerificationError) -> AppError {
    match error {
        HttpMessageVerificationError::MissingHeader("Signature-Input" | "Signature") => {
            mimi_signature_error_required(error.to_string())
        }
        HttpMessageVerificationError::Signature(
            SignatureError::MissingSignatureInputParameter("created" | "expires"),
        )
        | HttpMessageVerificationError::Policy(
            SignaturePolicyError::InvalidValidityWindow
            | SignaturePolicyError::CreatedInFuture
            | SignaturePolicyError::CreatedTooOld
            | SignaturePolicyError::Expired,
        ) => mimi_signature_error_window(error.to_string()),
        _ => mimi_signature_error_invalid(error.to_string()),
    }
}

pub(super) fn mimi_resolve_verifying_key(
    state: &AppState,
    verification_method: &str,
) -> Result<ed25519_dalek::VerifyingKey, AppError> {
    if let Ok(key) = crate::jws_verify::resolve_ed25519_pubkey(state, verification_method) {
        return Ok(key);
    }
    if state.config().development_mode {
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
