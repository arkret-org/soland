//! Inbound transaction-push per-delivery RFC 9421 source-signature
//! verification (`applet-integration.md` §7.3.1).

use cokret_sdk::applet::WebhookSignatureAlg;
use cokret_sdk::{AppletTransactionRequestBody, canonical};
use salvo::http::StatusCode;
use salvo::prelude::*;

use super::record::applet_records;
use super::types::AppletRecord;
use crate::error::AppError;
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
/// `source-service-did`, `destination-service-did`, `idempotency-key`, plus the
/// `created` / `expires` signature params. Failure codes (all 401 with the
/// discriminating `reason`, `error.code` stays generic `unauthenticated`):
/// - missing `Signature` / bearer-only → `http_signature_required`
/// - bad signature / `content-digest` mismatch / `source_service_did` header↔body mismatch →
///   `http_signature_invalid`
/// - `created` / `expires` outside the freshness window → `signature_window_invalid`
/// - `Source-Service-DID` with no active effective install / not matching the registration service
///   DID → 403 `applet_registration_unauthorized`.
pub(super) async fn verify_inbound_transaction_signature(
    state: &AppState,
    req: &Request,
    transaction: &AppletTransactionRequestBody,
    idempotency_key: &str,
) -> Result<VerifiedInboundTransactionSignature, AppError> {
    let source_service_did = transaction.source_service_did.as_str();

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
    let body_bytes = canonical::canonical_json_bytes(&body_value).map_err(|error| {
        AppError::invalid_param(format!(
            "applet transaction body is not canonical JSON: {error}"
        ))
    })?;
    let request_digest = canonical::sha256_digest(&body_bytes);
    let expected_content_digest = applet_content_digest_header(&body_bytes);
    let content_digest = applet_required_header(req, "content-digest")?;
    if content_digest != expected_content_digest {
        return Err(applet_signature_error_invalid(
            "Content-Digest does not cover the canonical inbound transaction body",
        ));
    }

    // Bound trust headers MUST be consistent with the body / this service
    // (`http_signature_invalid`).
    let header_source = applet_required_header(req, "source-service-did")?;
    if header_source != source_service_did {
        return Err(applet_signature_error_invalid(
            "Source-Service-DID header does not match the transaction source_service_did",
        ));
    }
    let header_idempotency = applet_required_header(req, "idempotency-key")?;
    if header_idempotency != idempotency_key {
        return Err(applet_signature_error_invalid(
            "Idempotency-Key header does not match the signed transcript binding",
        ));
    }
    let destination_service_did = applet_required_header(req, "destination-service-did")?;
    if destination_service_did != state.config.service_did {
        return Err(applet_signature_error_invalid(
            "Destination-Service-DID does not match this edge service",
        ));
    }

    // §7.3.1 anchor: when an active install exists, the signing key must be
    // the installed package webhook key controlled by `source_service_did`.
    // The no-install branch keeps authentication failure ordering stable; the
    // request still fails the active-install gate below.
    let install = active_install_for_service_did(state, source_service_did).await?;
    let verification_method = install
        .as_ref()
        .map(|install| applet_registration_verification_method(install, source_service_did))
        .transpose()?
        .unwrap_or_else(|| format!("{source_service_did}#applet-service-key"));

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
        source_service_did,
        &destination_service_did,
        idempotency_key,
        &signature_params,
    );
    applet_verify_signature_header(state, req, &verification_method, &signature_base)?;

    // §7.3.1: a verified signature is not yet authorisation — the
    // `Source-Service-DID` MUST also hit an active effective install whose
    // registration service DID equals it (§4b.1). fail closed otherwise.
    let Some(install) = install else {
        return Err(AppError::capability_denied(
            "Source-Service-DID has no active effective install on this edge",
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
        source_service_did,
        &destination_service_did,
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
/// DID equals `source_service_did`. The registration carries the service DID in
/// its installed package; manifest-only registrations (no package) are not an
/// install for §7.3.1 purposes and are skipped.
pub(super) async fn active_install_for_service_did(
    state: &AppState,
    source_service_did: &str,
) -> Result<Option<AppletRecord>, AppError> {
    Ok(applet_records(state).await?.into_iter().find(|record| {
        record.revoked_at.is_none()
            && matches!(record.status.as_str(), "installed" | "partially_installed")
            && record
                .package
                .as_ref()
                .map(|package| package.service_did.as_str() == source_service_did)
                .unwrap_or(false)
    }))
}

/// Resolve the verification method to verify the inbound signature against.
///
/// §7.3.1 anchor: the Applet registration `service_did`'s installed
/// `webhook_auth.key_ref` must name the source service DID's method and the
/// installed auth metadata must accept the algorithm this verifier implements.
pub(super) fn applet_registration_verification_method(
    install: &AppletRecord,
    source_service_did: &str,
) -> Result<String, AppError> {
    let package = install.package.as_ref().ok_or_else(|| {
        applet_signature_error_invalid("active applet install is missing package webhook auth")
    })?;
    let key_ref = package.webhook_auth.key_ref.trim();
    let expected_fragment_prefix = format!("{source_service_did}#");
    if key_ref.is_empty()
        || (key_ref != source_service_did && !key_ref.starts_with(&expected_fragment_prefix))
    {
        return Err(applet_signature_error_invalid(
            "Applet webhook_auth.key_ref must be controlled by Source-Service-DID",
        ));
    }
    if !package
        .webhook_auth
        .accepted_algs
        .iter()
        .any(|alg| *alg == WebhookSignatureAlg::EdDsa)
    {
        return Err(applet_signature_error_invalid(
            "Applet webhook_auth.accepted_algs must include EdDSA for inbound transaction signatures",
        ));
    }
    Ok(key_ref.to_owned())
}

pub(super) fn applet_content_digest_header(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    // RFC 9421 Content-Digest: `sha-256=:<base64(sha256(body))>:`.
    let raw = Sha256::digest(bytes);
    format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn applet_source_signature_anchor(
    source_service_did: &str,
    destination_service_did: &str,
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
        "profile": "ck.applet.source_signature_anchor.v1",
        "operation_id": "ck.edge.applet.command.transaction",
        "direction": "applet_to_cokret_inbound",
        "source_service_did": source_service_did,
        "destination_service_did": destination_service_did,
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
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            applet_signature_error_invalid(format!(
                "missing required inbound signature header: {name}"
            ))
        })
}

pub(super) fn applet_signature_params(req: &Request) -> Result<String, AppError> {
    let raw = req
        .headers()
        .get("signature-input")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| applet_signature_error_required("missing Signature-Input header"))?;
    raw.strip_prefix("sig1=")
        .map(ToOwned::to_owned)
        .ok_or_else(|| applet_signature_error_invalid("Signature-Input must carry sig1 parameters"))
}

pub(super) fn applet_signature_param_value(signature_params: &str, key: &str) -> Option<String> {
    signature_params.split(';').skip(1).find_map(|part| {
        let (name, value) = part.split_once('=')?;
        if name.trim() != key {
            return None;
        }
        Some(value.trim().trim_matches('"').to_owned())
    })
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
    let now = chrono::Utc::now().timestamp();
    let created = applet_signature_param_value(signature_params, "created")
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| {
            applet_signature_error_window("Signature-Input missing required `created` parameter")
        })?;
    let expires = applet_signature_param_value(signature_params, "expires")
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| {
            applet_signature_error_window("Signature-Input missing required `expires` parameter")
        })?;
    if (created - now).abs() > 30 {
        return Err(applet_signature_error_window(
            "signature created timestamp outside ±30s clock-skew window",
        ));
    }
    if expires < created || expires - created > 300 {
        return Err(applet_signature_error_window(
            "signature validity window exceeds 300s",
        ));
    }
    if expires < now {
        return Err(applet_signature_error_window("signature is expired"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn applet_http_signature_base(
    method: &str,
    target_uri: &str,
    authority: &str,
    content_digest: &str,
    source_service_did: &str,
    destination_service_did: &str,
    idempotency_key: &str,
    signature_params: &str,
) -> String {
    format!(
        "\"@method\": {method}\n\
         \"@target-uri\": {target_uri}\n\
         \"@authority\": {authority}\n\
         \"content-digest\": {content_digest}\n\
         \"source-service-did\": {source_service_did}\n\
         \"destination-service-did\": {destination_service_did}\n\
         \"idempotency-key\": {idempotency_key}\n\
         \"@signature-params\": {signature_params}",
    )
}

pub(super) fn applet_verify_signature_header(
    state: &AppState,
    req: &Request,
    verification_method: &str,
    signature_base: &str,
) -> Result<(), AppError> {
    use ed25519_dalek::Verifier as _;
    let signature_header = applet_required_header(req, "signature")?;
    let signature = applet_decode_signature_header(&signature_header).map_err(|message| {
        applet_signature_error_invalid(format!("signature decode: {message}"))
    })?;
    let verifying_key = applet_resolve_verifying_key(state, verification_method)?;
    verifying_key
        .verify(signature_base.as_bytes(), &signature)
        .map_err(|_| applet_signature_error_invalid("signature verification failed"))
}

pub(super) fn applet_decode_signature_header(
    value: &str,
) -> Result<ed25519_dalek::Signature, &'static str> {
    use base64::Engine as _;
    let signature_b64 = value
        .strip_prefix("sig1=:")
        .and_then(|value| value.strip_suffix(':'))
        .ok_or("Signature header must use sig1=:base64: form")?;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|_| "Signature header base64 is invalid")?;
    ed25519_dalek::Signature::from_slice(&signature_bytes)
        .map_err(|_| "Signature header is not Ed25519 length")
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
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"soland:applet-service-key:");
        hasher.update(verification_method.as_bytes());
        let seed: [u8; 32] = hasher.finalize().into();
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
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
