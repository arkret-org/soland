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
//! Stream-F-7 (`_todos.md`): blob metadata still misses the spec B-23
//! `space_id` association, and plaintext-visibility is enforced at write
//! time but not at GC.

use salvo::http::{Method, StatusCode};
use salvo::prelude::*;
use serde_json::json;

use super::{
    append_audit_log, auth_or_render, is_valid_sha256_digest, is_valid_sha256_hex, now,
    query_param, render_error, sha256_hex, space_allows_plaintext_service, space_has_member,
    validate_space_id,
};
use crate::state::{AppState, BlobRecord, SessionRecord};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("blob/upload").post(blob_upload))
        .push(Router::with_path("blob/get").get(blob_get).head(blob_get))
}

#[endpoint]
async fn blob_upload(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
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
    let media_type = req
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .and_then(sanitize_media_type)
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    let filename = match sanitized_blob_filename(req) {
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
            if !space_has_member(state, &space_id, &session.actor) {
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
    if let Err(message) = enforce_blob_quota(state, &session.actor, space_id.as_deref(), size) {
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
    if !encrypted
        && space_id
            .as_deref()
            .is_some_and(|space_id| !space_allows_plaintext_service(state, space_id))
    {
        render_error(
            res,
            StatusCode::FORBIDDEN,
            "policy_denied",
            "private plaintext blob uploads require this service in plaintext_visible_services",
        );
        return;
    }
    let sha256 = sha256_hex(&bytes);
    match expected_blob_sha256(req) {
        Ok(Some(expected_sha256)) if expected_sha256 != sha256 => {
            render_error(
                res,
                StatusCode::CONFLICT,
                "hash_mismatch",
                "provided sha256 does not match blob content",
            );
            return;
        }
        Ok(_) => {}
        Err(message) => {
            render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
            return;
        }
    }
    let blob_ref = format!("cx:blob:sha256:{sha256}");
    let storage_key = state.object_storage.object_key_for_sha256(&sha256);
    if let Err(error) = state.object_storage.put(&storage_key, bytes).await {
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "blob_store_error",
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
    if let Err(error) = state.persistence.blobs().put(&blob_ref, &record) {
        tracing::error!(%error, "failed to persist blob");
        if let Err(delete_error) = state.object_storage.delete(&storage_key).await {
            tracing::warn!(%delete_error, %storage_key, "failed to clean up blob after metadata write failure");
        }
        render_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "blob_store_error",
            &error.to_string(),
        );
        return;
    }
    res.render(Json(crate::wire::BlobUploadResponse {
        blob_ref,
        size,
        media_type,
        sha256,
        upload_receipt: json!({
            "service_did": state.config.service_did.clone(),
            "created_at": now(),
            "encrypted_attachment": encryption,
            "encrypted": encrypted,
            "filename": filename,
            "space_id": space_id,
        }),
    }));
}

#[endpoint]
async fn blob_get(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else {
        return;
    };
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
    let blob = state.persistence.blobs().get(&blob_ref).ok().flatten();
    match blob.as_ref() {
        Some(blob) => {
            if !blob_visible_to_session(
                state,
                blob,
                &session,
                query_param(req, "space_id").as_deref(),
            ) {
                render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
                return;
            }
            let total_len = match usize::try_from(blob.size_bytes) {
                Ok(total_len) => total_len,
                Err(_) => {
                    render_error(
                        res,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "blob_store_error",
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
            // Set Content-Disposition: attachment for HTML/JS/SVG to prevent stored XSS
            let dangerous_types = ["text/html", "application/javascript", "image/svg+xml"];
            if dangerous_types.contains(&blob.media_type.as_str()) {
                res.headers_mut().insert(
                    salvo::http::header::CONTENT_DISPOSITION,
                    "attachment".parse().unwrap(),
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
                Some(&session.actor),
                "blob.get",
                json!({
                    "blob_ref": blob_ref.clone(),
                    "device_id": session.device_id.clone(),
                    "purpose": purpose,
                    "space_id": blob.space_id.clone(),
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
                            "blob_store_error",
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
                        "blob_store_error",
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

fn expected_blob_sha256(req: &Request) -> Result<Option<String>, &'static str> {
    if let Some(value) = req
        .headers()
        .get("x-contrix-sha256")
        .and_then(|value| value.to_str().ok())
    {
        let digest = value.trim();
        if !is_valid_sha256_digest(digest) {
            return Err("x-contrix-sha256 must be sha256:<64 lowercase hex>");
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
        if !envelope
            .get(field)
            .and_then(|value| value.as_str())
            .is_some_and(|value| !value.trim().is_empty())
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

fn enforce_blob_quota(
    state: &AppState,
    actor: &str,
    space_id: Option<&str>,
    size: usize,
) -> Result<(), &'static str> {
    let blobs = state
        .persistence
        .blobs()
        .snapshot_all()
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

fn blob_visible_to_session(
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
    space_has_member(state, space_id, &session.actor)
}
