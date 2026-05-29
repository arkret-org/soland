//! Blob upload + download handlers.
//!
//! Surfaces:
//! - `POST /api/v1/blob/upload`         — multipart-or-raw upload, normalises MIME / filename,
//!   enforces per-actor / per-space / per-upload quotas, rejects plaintext blobs in private Spaces
//!   unless this service is in `plaintext_visible_services`.
//! - `HEAD /api/v1/blob/get`            — metadata + size for range planning
//! - `GET  /api/v1/blob/get`            — content (supports `Range` and the `?purpose=`
//!   discriminator)
//!
//! Blob metadata carries the spec `space_id` association; plaintext-visibility
//! is enforced at write time but not at GC.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signer;
use salvo::http::{Method, StatusCode};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{
    append_audit_log, auth_or_render, authenticated_session, is_valid_sha256_digest,
    is_valid_sha256_hex, now, query_param, render_error, sha256_hex,
    space_allows_plaintext_service, space_has_member, validate_space_id,
};
use crate::error::AppError;
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, BlobRecord, SessionRecord};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("blob/upload").post(blob_upload))
        .push(Router::with_path("blob/presign").post(blob_presign))
        .push(Router::with_path("blob/get").get(blob_get).head(blob_get))
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "blob_upload"))]
async fn blob_upload(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res).await else {
        return;
    };
    req.set_secure_max_size(MAX_BLOB_UPLOAD_BYTES);
    let bytes = match req.payload().await {
        Ok(bytes) => bytes.to_vec(),
        Err(_) => {
            render_error(
                res,
                StatusCode::BAD_REQUEST,
                "bad_json",
                "invalid blob body",
            );
            return;
        }
    };
    let requested_media_type = req
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .and_then(sanitize_media_type)
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    let requested_filename = match sanitized_blob_filename(req) {
        Ok(filename) => filename,
        Err(message) => {
            render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
            return;
        }
    };
    let space_id = match req
        .headers()
        .get("x-contrix-space-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
    {
        Some(space_id) => {
            if validate_space_id(&space_id).is_err() {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "invalid blob space_id",
                );
                return;
            }
            if !space_has_member(state, &space_id, &session.actor).await {
                render_error(
                    res,
                    StatusCode::FORBIDDEN,
                    "capability_denied",
                    "uploader is not a joined member of the blob space",
                );
                return;
            }
            Some(space_id)
        }
        None => None,
    };
    let size = bytes.len();
    if size > MAX_BLOB_UPLOAD_BYTES {
        render_error(
            res,
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "blob exceeds maximum size",
        );
        return;
    }
    if let Err(message) = enforce_blob_quota(state, &session.actor, space_id.as_deref(), size).await
    {
        render_error(
            res,
            StatusCode::PAYLOAD_TOO_LARGE,
            "quota_exceeded",
            message,
        );
        return;
    }
    let encryption = match encrypted_attachment_metadata(req) {
        Ok(encryption) => encryption,
        Err(message) => {
            render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
            return;
        }
    };
    let encrypted_flag = match blob_encrypted_flag(req) {
        Ok(flag) => flag,
        Err(message) => {
            render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
            return;
        }
    };
    let encrypted = encryption.is_some() || encrypted_flag.unwrap_or(false);
    if encrypted_flag == Some(true) && encryption.is_none() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "encrypted blob uploads require x-contrix-attachment-envelope",
        );
        return;
    }
    if encrypted_flag == Some(false) && encryption.is_some() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "x-contrix-blob-encrypted=false conflicts with encrypted attachment metadata",
        );
        return;
    }
    let media_type = if encrypted {
        "application/octet-stream".to_owned()
    } else {
        requested_media_type
    };
    let filename = if encrypted { None } else { requested_filename };
    let plaintext_denied = if encrypted {
        false
    } else if let Some(space_id) = space_id.as_deref() {
        !space_allows_plaintext_service(state, space_id).await
    } else {
        false
    };
    if plaintext_denied {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "policy_denied",
            "private plaintext blob uploads require this service in plaintext_visible_services",
        );
        return;
    }
    let sha256 = sha256_hex(&bytes);
    let content_digest = format!("sha256:{sha256}");
    match expected_blob_content_digest(req) {
        Ok(Some(expected_sha256)) if expected_sha256 != sha256 => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "digest_mismatch",
                "provided content_digest does not match blob content",
            );
            return;
        }
        Ok(_) => {}
        Err(message) => {
            render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
            return;
        }
    }
    if let Some(encryption) = encryption.as_ref() {
        if encryption
            .get("ciphertext_digest")
            .and_then(Value::as_str)
            .is_some_and(|digest| digest != content_digest)
        {
            render_error(
                res,
                StatusCode::CONFLICT,
                "digest_mismatch",
                "attachment ciphertext_digest does not match blob content",
            );
            return;
        }
    }
    let blob_ref = format!("cx:blob:sha256:{sha256}");
    let storage_key = state.object_storage.object_key_for_sha256(&sha256);
    if let Err(error) = state.object_storage.put(&storage_key, bytes).await {
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &error.to_string(),
        );
        return;
    }
    let record = BlobRecord {
        sha256: sha256.clone(),
        size_bytes: size as i64,
        storage_backend: state.object_storage.backend_name().to_owned(),
        storage_key: storage_key.clone(),
        media_type: media_type.clone(),
        filename: filename.clone(),
        space_id: space_id.clone(),
        encryption: encryption.clone(),
        uploaded_by: session.actor,
        created_at: now(),
    };
    if let Err(error) = state.persistence.blobs().put(&blob_ref, &record).await {
        tracing::error!(%error, "failed to persist blob");
        if let Err(delete_error) = state.object_storage.delete(&storage_key).await {
            tracing::warn!(%delete_error, %storage_key, "failed to clean up blob after metadata write failure");
        }
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &error.to_string(),
        );
        return;
    }
    let mut upload_receipt = json!({
        "service_did": state.config.service_did.clone(),
        "created_at": now(),
        "encrypted_attachment": encryption,
        "encrypted": encrypted,
        "space_id": space_id,
        "content_digest": content_digest.clone(),
    });
    if !encrypted && let Some(filename) = filename {
        upload_receipt["filename"] = json!(filename);
    }
    res.render(Json(crate::wire::BlobUploadResBody {
        blob_ref,
        size_bytes: size,
        media_type,
        content_digest,
        upload_receipt,
    }));
}

#[endpoint]
#[tracing::instrument(skip_all, fields(op = "blob_get"))]
async fn blob_get(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(blob_ref) = query_param(req, "blob_ref") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "blob_ref is required",
        );
        return;
    };
    let Some(purpose) = query_param(req, "purpose") else {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "missing_param",
            "purpose is required",
        );
        return;
    };
    if !is_valid_blob_purpose(&purpose) {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "invalid blob purpose",
        );
        return;
    }
    let presigned = validate_presign_query(state, req, &blob_ref, &purpose);
    let session = match authenticated_session(state, req).await {
        Ok(session) => Some(session),
        Err(_) if presigned => None,
        Err(_) => {
            render_error(
                res,
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "missing bearer token",
            );
            return;
        }
    };
    let blob = state
        .persistence
        .blobs()
        .get(&blob_ref)
        .await
        .ok()
        .flatten();
    match blob.as_ref() {
        Some(blob) => {
            let denied = if let Some(session) = session.as_ref() {
                !blob_visible_to_session(
                    state,
                    blob,
                    session,
                    query_param(req, "space_id").as_deref(),
                )
                .await
            } else {
                false
            };
            if denied {
                render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
                return;
            }
            // Round R2/R3 (T11) — fail-closed gates for E2EE / legal_hold /
            // redacted / actor_private. The blob_get path here serves the
            // bytes directly rather than issuing a presign URL; the gates +
            // headers below give the spec-required protection even for the
            // direct-serve path. TODO(round23-T11): wire dedicated presign
            // endpoint once object storage backend supports it; for now
            // direct-serve carries the same response shape requirements.
            let blob_value = presign_blob_policy_value(blob);
            let actor = session
                .as_ref()
                .map(|session| session.actor.as_str())
                .unwrap_or("presigned");
            if let Some(block) = crate::round23::classify_presign_blob_block(&blob_value, actor) {
                let direct_member_e2ee_download =
                    session.is_some() && matches!(block, crate::round23::PresignBlobBlock::E2ee);
                if !direct_member_e2ee_download {
                    let (code, reason) = block.as_error();
                    render_error(
                        res,
                        crate::error::error_http_status(code),
                        code.as_str(),
                        reason,
                    );
                    return;
                }
            }
            // Response headers per T11.
            res.headers_mut().insert(
                salvo::http::header::CACHE_CONTROL,
                crate::round23::PRESIGN_CACHE_CONTROL.parse().unwrap(),
            );
            res.headers_mut().insert(
                salvo::http::header::REFERRER_POLICY,
                crate::round23::PRESIGN_REFERRER_POLICY.parse().unwrap(),
            );
            let total_len = match usize::try_from(blob.size_bytes) {
                Ok(total_len) => total_len,
                Err(_) => {
                    render_error(
                        res,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "invalid blob size metadata",
                    );
                    return;
                }
            };
            let range = match parse_range(req, total_len).transpose() {
                Ok(range) => range,
                Err(message) => {
                    render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
                    return;
                }
            };
            let (status, content_length, content_range) = match range {
                Some((start, end)) => (
                    StatusCode::PARTIAL_CONTENT,
                    end.saturating_sub(start) + 1,
                    Some(format!("bytes {start}-{end}/{total_len}")),
                ),
                None => (StatusCode::OK, total_len, None),
            };
            res.status_code(status);
            res.headers_mut().insert(
                salvo::http::header::CONTENT_TYPE,
                blob.media_type.parse().unwrap(),
            );
            res.headers_mut().insert(
                salvo::http::header::CONTENT_LENGTH,
                content_length.to_string().parse().unwrap(),
            );
            res.headers_mut().insert(
                salvo::http::header::HeaderName::from_static("digest"),
                format!("sha-256={}", blob_ref.trim_start_matches("cx:blob:sha256:"))
                    .parse()
                    .unwrap(),
            );
            res.headers_mut().insert(
                salvo::http::header::HeaderName::from_static("accept-ranges"),
                "bytes".parse().unwrap(),
            );
            if let Some(disposition) = blob_content_disposition(blob, &purpose) {
                res.headers_mut().insert(
                    salvo::http::header::CONTENT_DISPOSITION,
                    disposition.parse().unwrap(),
                );
            }
            if let Some(content_range) = content_range {
                res.headers_mut().insert(
                    salvo::http::header::CONTENT_RANGE,
                    content_range.parse().unwrap(),
                );
            }
            append_audit_log(
                state,
                session.as_ref().map(|session| session.actor.as_str()),
                "blob.get",
                json!({
                    "blob_ref": blob_ref.clone(),
                    "device_id": session.as_ref().map(|session| session.device_id.clone()),
                    "purpose": purpose,
                    "space_id": blob.space_id.clone(),
                    "presigned": session.is_none(),
                    "status": status.as_u16()
                }),
                "accepted",
            );
            if req.method() != Method::HEAD {
                let blob_bytes = match state.object_storage.get(&blob.storage_key).await {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        tracing::error!(%error, storage_key = %blob.storage_key, "failed to read blob object");
                        render_error(
                            res,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            "blob object unavailable",
                        );
                        return;
                    }
                };
                if blob_bytes.len() != total_len {
                    tracing::error!(
                        storage_key = %blob.storage_key,
                        expected = total_len,
                        actual = blob_bytes.len(),
                        "blob object size differs from metadata"
                    );
                    render_error(
                        res,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal_error",
                        "blob object size metadata mismatch",
                    );
                    return;
                }
                let body = match range {
                    Some((start, end)) => blob_bytes[start..=end].to_vec(),
                    None => blob_bytes,
                };
                res.write_body(body).ok();
            }
        }
        None => render_error(res, StatusCode::NOT_FOUND, "not_found", "not found"),
    }
}

#[endpoint(
    operation_id = "cx.blob.presign",
    tags("blob"),
    summary = "Issue a short-lived presigned blob download URL"
)]
#[tracing::instrument(skip_all, fields(op = "cx.blob.presign"))]
async fn blob_presign(
    aa: crate::routing::system::extract::AuthArgs,
    body: JsonBody<Value>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Value> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let blob_ref = body
        .get("blob_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("blob_ref is required"))?;
    let purpose = body
        .get("purpose")
        .and_then(Value::as_str)
        .unwrap_or("download");
    if !is_valid_blob_purpose(purpose) {
        return Err(AppError::invalid_param("invalid blob purpose"));
    }
    let blob = state
        .persistence
        .blobs()
        .get(blob_ref)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| AppError::not_found("blob not found"))?;
    if !blob_visible_to_session(
        state,
        &blob,
        &session,
        body.get("space_id").and_then(Value::as_str),
    )
    .await
    {
        return Err(AppError::not_found("blob not found"));
    }
    let blob_value = presign_blob_policy_value(&blob);
    if let Some(block) = crate::round23::classify_presign_blob_block(&blob_value, &session.actor) {
        let (code, reason) = block.as_error();
        return Err(AppError::new(code, reason));
    }
    let ttl_seconds = body
        .get("ttl_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(300)
        .clamp(1, 300);
    let expires_at = now() + chrono::Duration::seconds(ttl_seconds as i64);
    let token = presign_token(state, blob_ref, purpose, expires_at.timestamp());
    let base = state.config.public_base_url.trim_end_matches('/');
    let url = format!(
        "{base}/api/v1/blob/get?blob_ref={}&purpose={}&expires_at={}&presign_token={}",
        query_escape(blob_ref),
        query_escape(purpose),
        expires_at.timestamp(),
        token,
    );
    json_ok(json!({
        "url": url,
        "method": "GET",
        "expires_at": expires_at.to_rfc3339(),
        "cache_control": crate::round23::PRESIGN_CACHE_CONTROL,
        "referrer_policy": crate::round23::PRESIGN_REFERRER_POLICY,
        "blob_ref": blob_ref,
        "purpose": purpose,
    }))
}

fn validate_presign_query(state: &AppState, req: &Request, blob_ref: &str, purpose: &str) -> bool {
    let Some(expires_at) =
        query_param(req, "expires_at").and_then(|value| value.parse::<i64>().ok())
    else {
        return false;
    };
    if expires_at <= now().timestamp() {
        return false;
    }
    let Some(token) = query_param(req, "presign_token") else {
        return false;
    };
    token == presign_token(state, blob_ref, purpose, expires_at)
}

fn presign_token(state: &AppState, blob_ref: &str, purpose: &str, expires_at: i64) -> String {
    let signing_input = presign_signing_input(state, blob_ref, purpose, expires_at);
    let signature = state.anchorer_signing_key().sign(signing_input.as_bytes());
    URL_SAFE_NO_PAD.encode(signature.to_bytes())
}

fn presign_signing_input(
    state: &AppState,
    blob_ref: &str,
    purpose: &str,
    expires_at: i64,
) -> String {
    format!(
        "soland.blob.presign.v1\nservice_did={}\ntrust_domain={}\nblob_ref={}\npurpose={}\nexpires_at={}",
        state.config.service_did, state.config.trust_domain, blob_ref, purpose, expires_at
    )
}

fn presign_blob_policy_value(blob: &BlobRecord) -> Value {
    json!({
        "encryption": blob.encryption.clone(),
        "uploaded_by": blob.uploaded_by.clone(),
        "legal_hold": false,
        "redacted": false,
        "visibility": null,
    })
}

fn query_escape(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(':', "%3A")
        .replace('/', "%2F")
        .replace(' ', "%20")
        .replace('&', "%26")
        .replace('=', "%3D")
}

fn blob_content_disposition(blob: &BlobRecord, purpose: &str) -> Option<String> {
    let dangerous_types = ["text/html", "application/javascript", "image/svg+xml"];
    let force_attachment =
        dangerous_types.contains(&blob.media_type.as_str()) || purpose != "profile_avatar";
    let disposition = if force_attachment {
        "attachment"
    } else {
        "inline"
    };
    match blob
        .filename
        .as_deref()
        .and_then(|filename| sanitize_blob_filename_value(filename).ok())
    {
        Some(filename) => Some(format!("{disposition}; filename=\"{filename}\"")),
        None if force_attachment => Some("attachment".to_owned()),
        None => None,
    }
}

fn expected_blob_content_digest(req: &Request) -> Result<Option<String>, &'static str> {
    if let Some(value) = req
        .headers()
        .get("x-contrix-content-digest")
        .and_then(|value| value.to_str().ok())
    {
        let digest = value.trim();
        if !is_valid_sha256_digest(digest) {
            return Err("x-contrix-content-digest must be sha256:<64 lowercase hex>");
        }
        return Ok(Some(digest.trim_start_matches("sha256:").to_owned()));
    }
    if let Some(value) = req
        .headers()
        .get(salvo::http::header::HeaderName::from_static("digest"))
        .and_then(|value| value.to_str().ok())
    {
        let Some(digest) = value.trim().strip_prefix("sha-256=") else {
            return Err("digest must be sha-256=<64 lowercase hex>");
        };
        if !is_valid_sha256_hex(digest) {
            return Err("digest must be sha-256=<64 lowercase hex>");
        }
        return Ok(Some(digest.to_owned()));
    }
    Ok(None)
}

fn encrypted_attachment_metadata(req: &Request) -> Result<Option<serde_json::Value>, &'static str> {
    let Some(value) = req
        .headers()
        .get(salvo::http::header::HeaderName::from_static(
            "x-contrix-attachment-envelope",
        ))
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };
    let metadata: serde_json::Value =
        serde_json::from_str(value).map_err(|_| "attachment envelope must be JSON")?;
    validate_encrypted_attachment_metadata(&metadata)?;
    Ok(Some(metadata))
}

fn validate_encrypted_attachment_metadata(
    metadata: &serde_json::Value,
) -> Result<(), &'static str> {
    let Some(envelope) = metadata.as_object() else {
        return Err("attachment envelope must be a JSON object");
    };
    for field in ["algorithm", "nonce", "ciphertext_digest"] {
        if envelope
            .get(field)
            .and_then(|value| value.as_str())
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err("attachment envelope is missing required string fields");
        }
    }
    if !envelope
        .get("key_ref")
        .is_some_and(|value| value.is_object() || value.as_str().is_some())
    {
        return Err("attachment envelope requires key_ref");
    }
    if !envelope
        .get("ciphertext_digest")
        .and_then(|value| value.as_str())
        .is_some_and(is_valid_sha256_digest)
    {
        return Err("attachment ciphertext_digest must be sha256:<64 lowercase hex>");
    }
    Ok(())
}

fn parse_range(req: &Request, total_len: usize) -> Option<Result<(usize, usize), &'static str>> {
    let header = req
        .headers()
        .get(salvo::http::header::RANGE)?
        .to_str()
        .ok()?;
    let Some(range) = header.strip_prefix("bytes=") else {
        return Some(Err("only bytes ranges are supported"));
    };
    let Some((start, end)) = range.split_once('-') else {
        return Some(Err("invalid range"));
    };
    let start = match start.parse::<usize>() {
        Ok(value) => value,
        Err(_) => return Some(Err("invalid range start")),
    };
    let end = if end.is_empty() {
        total_len.saturating_sub(1)
    } else {
        match end.parse::<usize>() {
            Ok(value) => value,
            Err(_) => return Some(Err("invalid range end")),
        }
    };
    if total_len == 0 || start > end || end >= total_len {
        return Some(Err("range is outside blob bounds"));
    }
    Some(Ok((start, end)))
}

const MAX_BLOB_UPLOAD_BYTES: usize = 10 * 1024 * 1024;
const MAX_BLOB_ACCOUNT_BYTES: usize = 50 * 1024 * 1024;
const MAX_BLOB_SPACE_BYTES: usize = 100 * 1024 * 1024;

fn sanitize_media_type(raw: &str) -> Option<String> {
    let media_type = raw.split(';').next()?.trim().to_ascii_lowercase();
    let (top, sub) = media_type.split_once('/')?;
    (is_valid_mime_token(top) && is_valid_mime_token(sub)).then_some(media_type)
}

fn is_valid_mime_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || matches!(ch, '!' | '#' | '$' | '&' | '-' | '^' | '_' | '.' | '+')
        })
}

fn sanitized_blob_filename(req: &Request) -> Result<Option<String>, &'static str> {
    let raw = req
        .headers()
        .get("x-contrix-filename")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| {
            req.headers()
                .get(salvo::http::header::CONTENT_DISPOSITION)
                .and_then(|value| value.to_str().ok())
                .and_then(content_disposition_filename)
        });
    raw.map(|value| sanitize_blob_filename_value(&value))
        .transpose()
}

fn content_disposition_filename(value: &str) -> Option<String> {
    value.split(';').find_map(|part| {
        let part = part.trim();
        part.strip_prefix("filename=")
            .map(|filename| filename.trim_matches('"').to_owned())
    })
}

fn sanitize_blob_filename_value(value: &str) -> Result<String, &'static str> {
    let basename = value
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .trim()
        .trim_matches('"');
    let mut sanitized = String::new();
    for ch in basename.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
            sanitized.push(ch);
        } else if ch.is_ascii_whitespace() || ch.is_ascii_punctuation() {
            sanitized.push('_');
        }
        if sanitized.len() >= 128 {
            break;
        }
    }
    let sanitized = sanitized
        .trim_matches(|ch| matches!(ch, '.' | '_' | '-' | ' '))
        .to_owned();
    if sanitized.is_empty() {
        return Err("filename must contain at least one safe character");
    }
    Ok(sanitized)
}

fn blob_encrypted_flag(req: &Request) -> Result<Option<bool>, &'static str> {
    let Some(raw) = req
        .headers()
        .get("x-contrix-blob-encrypted")
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(Some(true)),
        "false" | "0" | "no" => Ok(Some(false)),
        _ => Err("x-contrix-blob-encrypted must be true or false"),
    }
}

async fn enforce_blob_quota(
    state: &AppState,
    actor: &str,
    space_id: Option<&str>,
    size: usize,
) -> Result<(), &'static str> {
    let blobs = state
        .persistence
        .blobs()
        .snapshot_all()
        .await
        .map_err(|_| "blob store unavailable")?;
    let actor_bytes: usize = blobs
        .iter()
        .filter(|blob| blob.uploaded_by == actor)
        .map(|blob| blob.size_bytes.max(0) as usize)
        .sum();
    if actor_bytes.saturating_add(size) > MAX_BLOB_ACCOUNT_BYTES {
        return Err("account blob quota exceeded");
    }
    if let Some(space_id) = space_id {
        let space_bytes: usize = blobs
            .iter()
            .filter(|blob| blob.space_id.as_deref() == Some(space_id))
            .map(|blob| blob.size_bytes.max(0) as usize)
            .sum();
        if space_bytes.saturating_add(size) > MAX_BLOB_SPACE_BYTES {
            return Err("space blob quota exceeded");
        }
    }
    Ok(())
}

fn is_valid_blob_purpose(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
}

async fn blob_visible_to_session(
    state: &AppState,
    blob: &BlobRecord,
    session: &SessionRecord,
    requested_space_id: Option<&str>,
) -> bool {
    if blob.uploaded_by == session.actor {
        return blob.space_id.as_deref().is_none_or(|space_id| {
            requested_space_id.is_none_or(|requested| requested == space_id)
        });
    }

    let Some(space_id) = blob.space_id.as_deref() else {
        return false;
    };
    if requested_space_id.is_some_and(|requested| requested != space_id) {
        return false;
    }
    space_has_member(state, space_id, &session.actor).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob_record(media_type: &str, filename: Option<&str>) -> BlobRecord {
        BlobRecord {
            sha256: "0".repeat(64),
            size_bytes: 1,
            storage_backend: "memory".to_owned(),
            storage_key: "sha256/test".to_owned(),
            media_type: media_type.to_owned(),
            filename: filename.map(ToOwned::to_owned),
            space_id: Some("cx:realm:0196419b-0000-7000-8000-000000000000".to_owned()),
            encryption: None,
            uploaded_by: "did:web:alice.example".to_owned(),
            created_at: now(),
        }
    }

    #[test]
    fn content_disposition_for_message_attachment_sanitizes_filename() {
        let blob = blob_record("text/plain", Some("..\\report final.txt"));
        assert_eq!(
            blob_content_disposition(&blob, "message_attachment").as_deref(),
            Some("attachment; filename=\"report_final.txt\"")
        );
    }

    #[test]
    fn content_disposition_for_safe_profile_avatar_can_inline() {
        let blob = blob_record("image/png", Some("avatar.png"));
        assert_eq!(
            blob_content_disposition(&blob, "profile_avatar").as_deref(),
            Some("inline; filename=\"avatar.png\"")
        );
    }

    #[test]
    fn content_disposition_for_dangerous_profile_avatar_forces_attachment() {
        let blob = blob_record("image/svg+xml", Some("avatar.svg"));
        assert_eq!(
            blob_content_disposition(&blob, "profile_avatar").as_deref(),
            Some("attachment; filename=\"avatar.svg\"")
        );
    }
}
