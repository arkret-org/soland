//! Inbound transaction-push per-delivery RFC 9421 source-signature
//! verification (`applet-integration.md` §7.3.1).

use arkret_sdk::applet::WebhookSignatureAlg;
use arkret_sdk::{AppletTransactionRequestBody, canonical};
use salvo::http::StatusCode;
use salvo::prelude::*;
use soland_http::error::AppError;
use soland_http::http_signature::{self, SignatureBaseComponent, SignatureWindowViolation};

use super::record::applet_records;
use super::types::AppletRecord;
use crate::state::AppState;

#[derive(Clone, Debug)]
pub(super) struct VerifiedInboundTransactionSignature {
    pub(super) install: AppletRecord,
    pub(super) request_digest: String,
    pub(super) source_signature_anchor: String,
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
pub(super) async fn verify_inbound_transaction_signature(
    state: &AppState,
    req: &Request,
    transaction: &AppletTransactionRequestBody,
    idempotency_key: &str,
) -> Result<VerifiedInboundTransactionSignature, AppError> {
    let source_service_id = transaction.source_service_id.as_str();

    // §7.3.1 ordering: a transaction push carrying only `Authorization: Bearer`
    // (no `Signature` / `Signature-Input`) MUST be rejected before any other
    // work. This is the cheapest, highest-priority gate and is what separates a
    // plain-bearer caller from a (mis)signed one.
    let signature_present =
        req.headers().get("signature").is_some() && req.headers().get("signature-input").is_some();
    if !signature_present {
        return Err(applet_signature_error_required(
            "inbound transaction push MUST carry an RFC 9421 Signature / Signature-Input; \
             plain bearer is rejected",
        ));
    }

    // §7.3.1 line 456: verify the body hash matches `Content-Digest` before
    // validating the signature transcript. The signed body MUST be the
    // canonical request body.
    let body_value = serde_json::to_value(transaction).map_err(|error| {
        AppError::internal(format!(
            "applet transaction body serialization failed: {error}"
        ))
    })?;
    let body_digests = http_signature::canonical_body_digests(&body_value, |error| {
        AppError::invalid_param(format!(
            "applet transaction body is not canonical JSON: {error}"
        ))
    })?;
    let request_digest = body_digests.request_digest;
    let expected_content_digest = body_digests.content_digest;
    let content_digest = applet_required_header(req, "content-digest")?;
    if content_digest != expected_content_digest {
        return Err(applet_signature_error_invalid(
            "Content-Digest does not cover the canonical inbound transaction body",
        ));
    }

    // Bound trust headers MUST be consistent with the body / this service
    // (`http_signature_invalid`).
    let header_source = applet_required_header(req, "source-service-id")?;
    if header_source != source_service_id {
        return Err(applet_signature_error_invalid(
            "Source-Service-ID header does not match the transaction source_service_id",
        ));
    }
    let header_idempotency = applet_required_header(req, "idempotency-key")?;
    if header_idempotency != idempotency_key {
        return Err(applet_signature_error_invalid(
            "Idempotency-Key header does not match the signed transcript binding",
        ));
    }
    let destination_service_id = applet_required_header(req, "destination-service-id")?;
    if destination_service_id != state.service_id {
        return Err(applet_signature_error_invalid(
            "Destination-Service-ID does not match this edge service",
        ));
    }

    // §7.3.1 anchor: when an active install exists, the signing key must be
    // the installed package webhook key controlled by `source_service_id`.
    // The no-install branch keeps authentication failure ordering stable; the
    // request still fails the active-install gate below.
    let install = active_install_for_service_id(state, source_service_id).await?;
    let verification_method = install
        .as_ref()
        .map(|install| applet_registration_verification_method(install, source_service_id))
        .transpose()?
        .unwrap_or_else(|| format!("{source_service_id}#applet-service-key"));

    // Validate signature params (keyid / alg / freshness window). Window
    // violations surface as `signature_window_invalid`.
    let signature_params = applet_signature_params(req)?;
    applet_validate_signature_params(&signature_params, &verification_method)?;

    let target_uri = crate::routing::federation::signature_target_uri(req, state);
    let authority = crate::routing::federation::signature_authority(req, state);
    let method = req.method().as_str().to_ascii_uppercase();
    let signature_base = applet_http_signature_base(
        &method,
        &target_uri,
        &authority,
        &content_digest,
        source_service_id,
        &destination_service_id,
        idempotency_key,
        &signature_params,
    );
    applet_verify_signature_header(state, req, &verification_method, &signature_base)?;

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
    let signature_alg = applet_signature_param_value(&signature_params, "alg").unwrap_or_default();
    let source_signature_anchor = applet_source_signature_anchor(
        source_service_id,
        &destination_service_id,
        idempotency_key,
        &content_digest,
        &request_digest,
        &verification_method,
        serde_json::to_value(&package.registration_epoch).unwrap_or(serde_json::Value::Null),
        serde_json::to_value(&package.webhook_auth).unwrap_or(serde_json::Value::Null),
        &signature_alg,
        &signature_params,
        &signature_header,
    );
    Ok(VerifiedInboundTransactionSignature {
        install,
        request_digest,
        source_signature_anchor,
    })
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
        .accepted_algs
        .contains(&WebhookSignatureAlg::EdDsa)
    {
        return Err(applet_signature_error_invalid(
            "Applet webhook_auth.accepted_algs must include EdDSA for inbound transaction signatures",
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
    signature_alg: &str,
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
        "signature_algorithm": signature_alg,
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

pub(super) fn applet_signature_params(req: &Request) -> Result<String, AppError> {
    http_signature::signature_params(
        req,
        "signature-input",
        || applet_signature_error_required("missing Signature-Input header"),
        || applet_signature_error_invalid("Signature-Input must carry sig1 parameters"),
    )
}

pub(super) fn applet_signature_param_value(signature_params: &str, key: &str) -> Option<String> {
    http_signature::signature_param_value(signature_params, key)
}

/// Validate the RFC 9421 signature params (§7.3.1): `alg=ed25519`, `keyid`
/// equals the registration verification method, and the freshness window
/// (`expires - created` ≤ 300s, `created` within ±30s, `expires` not past) per
/// `federation.md` §3.2. Window violations are `signature_window_invalid`;
/// keyid/alg mismatches are `http_signature_invalid`.
pub(super) fn applet_validate_signature_params(
    signature_params: &str,
    expected_verification_method: &str,
) -> Result<(), AppError> {
    let observed_keyid = applet_signature_param_value(signature_params, "keyid")
        .ok_or_else(|| applet_signature_error_invalid("Signature-Input missing keyid"))?;
    if observed_keyid != expected_verification_method {
        return Err(applet_signature_error_invalid(
            "Signature-Input keyid does not match the Applet registration verification method",
        ));
    }
    if applet_signature_param_value(signature_params, "alg").as_deref() != Some("ed25519") {
        return Err(applet_signature_error_invalid(
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
                "signature created timestamp outside ±30s clock-skew window"
            }
            SignatureWindowViolation::InvalidValidityWindow => {
                "signature validity window exceeds 300s"
            }
            SignatureWindowViolation::Expired => "signature is expired",
        };
        applet_signature_error_window(message)
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn applet_http_signature_base(
    method: &str,
    target_uri: &str,
    authority: &str,
    content_digest: &str,
    source_service_id: &str,
    destination_service_id: &str,
    idempotency_key: &str,
    signature_params: &str,
) -> String {
    http_signature::signature_base(
        &[
            SignatureBaseComponent::required("@method", method),
            SignatureBaseComponent::required("@target-uri", target_uri),
            SignatureBaseComponent::required("@authority", authority),
            SignatureBaseComponent::required("content-digest", content_digest),
            SignatureBaseComponent::required("source-service-id", source_service_id),
            SignatureBaseComponent::required("destination-service-id", destination_service_id),
            SignatureBaseComponent::required("idempotency-key", idempotency_key),
        ],
        signature_params,
    )
}

pub(super) fn applet_verify_signature_header(
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
            applet_signature_error_invalid(format!(
                "missing required inbound signature header: {name}"
            ))
        },
        |message| applet_signature_error_invalid(format!("signature decode: {message}")),
        || applet_signature_error_invalid("signature verification failed"),
        || applet_resolve_verifying_key(state, verification_method),
    )
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
    if state.config.development_mode {
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
