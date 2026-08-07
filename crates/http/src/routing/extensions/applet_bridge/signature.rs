//! Inbound transaction-push per-delivery RFC 9421 source-signature
//! verification (`applet-integration.md` §7.3.1).

use arkret_canonical as canonical;
use arkret_models_integration::applet::HttpMessageSignatureAlgorithm;
use arkret_signatures::http_signature::{
    Component, HttpMessageVerificationError, SignatureError, SignatureInput, SignaturePolicyError,
    SignatureVerificationPolicy,
};
use salvo::http::StatusCode;
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::http_signature;

use super::record::applet_records;
use super::types::AppletRecord;
use crate::state::AppState;

#[derive(Clone, Debug)]
pub(super) struct VerifiedInboundTransactionSignature {
    pub(super) install: AppletRecord,
    pub(super) request_digest: String,
    pub(super) source_signature_anchor: String,
}

#[handler]
pub(super) async fn require_inbound_transaction_signature(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let verification = async {
        if !inbound_transaction_signature_present(req) {
            return Err(applet_signature_error_required(
                "inbound transaction push MUST carry an RFC 9421 Signature / Signature-Input; \
                 plain bearer is rejected",
            ));
        }
        let state = depot
            .get_typed::<AppState>()
            .expect("state injected")
            .clone();
        let idempotency_key = applet_required_header(req, "idempotency-key")?;
        http_signature::reject_content_encoding(req, || {
            applet_signature_error_invalid(
                "applet signed JSON requests must not use Content-Encoding",
            )
        })?;
        let payload = req
            .payload()
            .await
            .map_err(|error| {
                AppError::bad_json(format!("unable to read applet transaction body: {error}"))
            })?
            .to_vec();
        verify_inbound_transaction_signature(&state, req, &payload, &idempotency_key).await
    }
    .await;

    match verification {
        Ok(verified) => {
            depot.insert_typed(verified);
            ctrl.call_next(req, depot, res).await;
        }
        Err(error) => error.write(req, depot, res).await,
    }
}

/// Inbound transaction-push per-delivery source-signature verification
/// (`applet-integration.md` §7.3.1).
///
/// Covered RFC 9421 components (MUST, symmetric with `federation.md` §3.2):
/// `@method`, `@target-uri`, `@authority`, `content-digest`,
/// `source-service-id`, `destination-service-id`, `idempotency-key`, plus the
/// `created` / `expires` signature params. Failure codes (all 401 with the
/// discriminating `reason`, `error.code` stays generic `unauthenticated`):
/// - missing `Signature` / bearer-only → `http_signature_required`
/// - bad signature / `content-digest` mismatch / `source_service_id` header↔body mismatch →
///   `http_signature_invalid`
/// - `created` / `expires` outside the freshness window → `signature_window_invalid`
/// - `Source-Service-ID` with no active effective install / not matching the registration service
///   DID → 403 `applet_registration_unauthorized`.
async fn verify_inbound_transaction_signature(
    state: &AppState,
    req: &Request,
    body_bytes: &[u8],
    idempotency_key: &str,
) -> Result<VerifiedInboundTransactionSignature, AppError> {
    // §7.3.1 ordering: a transaction push carrying only `Authorization: Bearer`
    // (no `Signature` / `Signature-Input`) MUST be rejected before any other
    // work. This is the cheapest, highest-priority gate and is what separates a
    // plain-bearer caller from a (mis)signed one.
    if !inbound_transaction_signature_present(req) {
        return Err(applet_signature_error_required(
            "inbound transaction push MUST carry an RFC 9421 Signature / Signature-Input; \
             plain bearer is rejected",
        ));
    }

    let request_digest = arkret_canonical::sha256_digest(body_bytes);
    // Bound trust headers select the verification key and MUST identify this
    // service. The body/header binding is checked after the shared verifier has
    // authenticated the canonical body bytes.
    let header_source = applet_required_header(req, "source-service-id")?;
    let header_idempotency = applet_required_header(req, "idempotency-key")?;
    if header_idempotency != idempotency_key {
        return Err(applet_signature_error_invalid(
            "Idempotency-Key header does not match the signed transcript binding",
        ));
    }
    let destination_service_id = applet_required_header(req, "destination-service-id")?;
    if destination_service_id != *state.service_id() {
        return Err(applet_signature_error_invalid(
            "Destination-Service-ID does not match this edge service",
        ));
    }

    // §7.3.1 anchor: when an active install exists, the signing key must be
    // the installed package webhook key controlled by `source_service_id`.
    // The no-install branch keeps authentication failure ordering stable; the
    // request still fails the active-install gate below.
    let install = active_install_for_service_id(state, &header_source).await?;
    let verification_method = install
        .as_ref()
        .map(|install| applet_registration_verification_method(install, &header_source))
        .transpose()?
        .unwrap_or_else(|| format!("{header_source}#applet-service-key"));

    let target_uri = crate::routing::federation::signature_target_uri(req, state);
    let authority = crate::routing::federation::signature_authority(req, state);
    let signature_input =
        http_signature::parse_signature_input_header(req).map_err(applet_verification_error)?;
    applet_validate_signature_input(&signature_input, &verification_method)?;
    let verifying_key = applet_resolve_verifying_key(state, &verification_method)?;
    let policy = SignatureVerificationPolicy::new(vec![
        Component::Method,
        Component::TargetUri,
        Component::Authority,
        Component::Header("content-digest".to_owned()),
        Component::Header("source-service-id".to_owned()),
        Component::Header("destination-service-id".to_owned()),
        Component::Header("idempotency-key".to_owned()),
    ]);
    let verified = http_signature::verify_signed_canonical_json_request(
        req,
        &target_uri,
        &authority,
        body_bytes,
        &verifying_key,
        &policy,
    )
    .map_err(applet_verification_error)?;
    let content_digest = verified
        .content_digest
        .as_ref()
        .expect("applet signature policy requires Content-Digest")
        .wire_value
        .as_str();

    let transaction = serde_json::from_slice::<serde_json::Value>(body_bytes).map_err(|error| {
        applet_signature_error_invalid(format!("invalid applet transaction JSON: {error}"))
    })?;
    let source_service_id = transaction
        .get("source_service_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            applet_signature_error_invalid(
                "signed applet transaction body requires source_service_id",
            )
        })?;
    if header_source != source_service_id {
        return Err(applet_signature_error_invalid(
            "Source-Service-ID header does not match the transaction source_service_id",
        ));
    }

    // §7.3.1: a verified signature is not yet authorisation — the
    // `Source-Service-ID` MUST also hit an active effective install whose
    // registration service DID equals it (§4b.1). fail closed otherwise.
    let Some(install) = install else {
        return Err(AppError::capability_denied(
            "Source-Service-ID has no active effective install on this edge",
        )
        .with_status(StatusCode::FORBIDDEN)
        .with_wire_code("applet_registration_unauthorized")
        .with_top_level_reason("applet_registration_unauthorized"));
    };
    let package = install
        .package
        .as_ref()
        .ok_or_else(|| AppError::internal("active applet install is missing its package record"))?;
    let signature_header = applet_required_header(req, "signature")?;
    let source_signature_anchor = applet_source_signature_anchor(
        source_service_id,
        &destination_service_id,
        idempotency_key,
        content_digest,
        &request_digest,
        &verification_method,
        serde_json::to_value(&package.registration_epoch).unwrap_or(serde_json::Value::Null),
        serde_json::to_value(&package.webhook_auth).unwrap_or(serde_json::Value::Null),
        &verified.signature_input.algorithm,
        &verified.signature_input.params_value,
        &signature_header,
    );
    Ok(VerifiedInboundTransactionSignature {
        install,
        request_digest,
        source_signature_anchor,
    })
}

fn inbound_transaction_signature_present(req: &Request) -> bool {
    req.headers().get("signature").is_some() && req.headers().get("signature-input").is_some()
}

/// Find an active (non-revoked) effective install whose registration service
/// DID equals `source_service_id`. The registration carries the service DID in
/// its installed package; manifest-only registrations (no package) are not an
/// install for §7.3.1 purposes and are skipped.
pub(super) async fn active_install_for_service_id(
    state: &AppState,
    source_service_id: &str,
) -> Result<Option<AppletRecord>, AppError> {
    Ok(applet_records(state).await?.into_iter().find(|record| {
        record.revoked_at.is_none()
            && matches!(record.status.as_str(), "installed" | "partially_installed")
            && record
                .package
                .as_ref()
                .map(|package| package.service_id.as_str() == source_service_id)
                .unwrap_or(false)
    }))
}

/// Resolve the verification method to verify the inbound signature against.
///
/// §7.3.1 anchor: the Applet registration `service_id`'s installed
/// `webhook_auth.key_ref` must name the source service DID's method and the
/// installed auth metadata must accept the algorithm this verifier implements.
pub(super) fn applet_registration_verification_method(
    install: &AppletRecord,
    source_service_id: &str,
) -> Result<String, AppError> {
    let package = install.package.as_ref().ok_or_else(|| {
        applet_signature_error_invalid("active applet install is missing package webhook auth")
    })?;
    let key_ref = package.webhook_auth.key_ref.trim();
    let expected_fragment_prefix = format!("{source_service_id}#");
    if key_ref.is_empty()
        || (key_ref != source_service_id && !key_ref.starts_with(&expected_fragment_prefix))
    {
        return Err(applet_signature_error_invalid(
            "Applet webhook_auth.key_ref must be controlled by Source-Service-ID",
        ));
    }
    if !package
        .webhook_auth
        .accepted_signature_algorithms
        .contains(&HttpMessageSignatureAlgorithm::Ed25519)
    {
        return Err(applet_signature_error_invalid(
            "Applet webhook_auth.accepted_signature_algorithms must include ed25519 for inbound transaction signatures",
        ));
    }
    Ok(key_ref.to_owned())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn applet_source_signature_anchor(
    source_service_id: &str,
    destination_service_id: &str,
    idempotency_key: &str,
    content_digest: &str,
    request_digest: &str,
    verification_method: &str,
    registration_epoch: serde_json::Value,
    webhook_auth: serde_json::Value,
    signature_algorithm: &str,
    signature_params: &str,
    signature_header: &str,
) -> String {
    let anchor = serde_json::json!({
        "profile": "ak.applet.source_signature_anchor.v1",
        "operation_id": "ak.edge.applet.command.transaction",
        "direction": "applet_to_arkret_inbound",
        "source_service_id": source_service_id,
        "destination_service_id": destination_service_id,
        "idempotency_key": idempotency_key,
        "content_digest": content_digest,
        "request_digest": request_digest,
        "verification_method": verification_method,
        "signature_algorithm": signature_algorithm,
        "registration_epoch": registration_epoch,
        "webhook_auth": webhook_auth,
        "signature_input": signature_params,
        "signature": signature_header,
    });
    canonical::canonical_sha256(&anchor).unwrap_or_else(|_| {
        let bytes = serde_json::to_vec(&anchor).unwrap_or_default();
        canonical::sha256_digest(&bytes)
    })
}

pub(super) fn applet_required_header(req: &Request, name: &str) -> Result<String, AppError> {
    http_signature::required_header(req, name, |name| {
        applet_signature_error_invalid(format!("missing required inbound signature header: {name}"))
    })
}

/// Apply the Applet registration binding after the SDK has parsed the RFC 9421
/// input. Algorithm, component coverage and freshness are owned by the shared
/// SDK verifier.
pub(super) fn applet_validate_signature_input(
    signature_input: &SignatureInput,
    expected_verification_method: &str,
) -> Result<(), AppError> {
    if signature_input.label != "sig1" {
        return Err(applet_signature_error_invalid(
            "Signature-Input must use the sig1 label",
        ));
    }
    if signature_input.key_id != expected_verification_method {
        return Err(applet_signature_error_invalid(
            "Signature-Input keyid does not match the Applet registration verification method",
        ));
    }
    Ok(())
}

fn applet_verification_error(error: HttpMessageVerificationError) -> AppError {
    match error {
        HttpMessageVerificationError::MissingHeader("Signature-Input" | "Signature") => {
            applet_signature_error_required(error.to_string())
        }
        HttpMessageVerificationError::Signature(
            SignatureError::MissingSignatureInputParameter("created" | "expires"),
        )
        | HttpMessageVerificationError::Policy(
            SignaturePolicyError::InvalidValidityWindow
            | SignaturePolicyError::CreatedInFuture
            | SignaturePolicyError::CreatedTooOld
            | SignaturePolicyError::Expired,
        ) => applet_signature_error_window(error.to_string()),
        _ => applet_signature_error_invalid(error.to_string()),
    }
}

/// Resolve the Ed25519 public key for the registration verification method via
/// the DID resolver. In `development_mode` a deterministic per-DID fallback key
/// is used (mirroring the federation path) so the joint e2e harness can drive
/// signed deliveries without a live DID document; a forged signature still
/// fails the cryptographic `verify`.
pub(super) fn applet_resolve_verifying_key(
    state: &AppState,
    verification_method: &str,
) -> Result<ed25519_dalek::VerifyingKey, AppError> {
    if let Ok(key) = crate::jws_verify::resolve_ed25519_pubkey(state, verification_method) {
        return Ok(key);
    }
    if state.config().development_mode {
        let signing = http_signature::deterministic_development_signing_key(
            b"soland:applet-service-key:",
            verification_method,
        );
        return Ok(signing.verifying_key());
    }
    Err(applet_signature_error_invalid(
        "Applet registration verification key is unavailable",
    ))
}

/// 401 `http_signature_required` — no per-delivery RFC 9421 signature present.
pub(super) fn applet_signature_error_required(message: impl Into<String>) -> AppError {
    AppError::unauthenticated(message)
        .with_status(StatusCode::UNAUTHORIZED)
        .with_top_level_reason("http_signature_required")
}

/// 401 `http_signature_invalid` — signature present but verification, digest,
/// or source binding failed.
pub(super) fn applet_signature_error_invalid(message: impl Into<String>) -> AppError {
    AppError::unauthenticated(message)
        .with_status(StatusCode::UNAUTHORIZED)
        .with_top_level_reason("http_signature_invalid")
}

/// 401 `signature_window_invalid` — `created` / `expires` outside the freshness
/// window.
pub(super) fn applet_signature_error_window(message: impl Into<String>) -> AppError {
    AppError::unauthenticated(message)
        .with_status(StatusCode::UNAUTHORIZED)
        .with_top_level_reason("signature_window_invalid")
}
