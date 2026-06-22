//! Blob upload + download handlers.
//!
//! Surfaces:
//! - `POST /_cokret/self/blob/upload`         — multipart-or-raw upload, normalises MIME /
//!   filename, enforces per-actor / per-Realm / per-upload quotas, rejects plaintext blobs in
//!   private Realms unless this service is in `plaintext_visible_services`.
//! - `HEAD /_cokret/self/blob/get`            — metadata + size for range planning
//! - `GET  /_cokret/self/blob/get`            — content (supports `Range` and the `?purpose=`
//!   discriminator)
//!
//! Blob metadata carries the spec `realm_id` association; plaintext-visibility
//! is enforced at write time but not at GC.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cokret_sdk::{
    BlobPresignAccessScope, BlobPresignDetachedJwsProof, BlobPresignEnvelope, BlobPresignOutcome,
    BlobPresignPayload, BlobPresignRequestBody, BlobRef, BlobUploadOutcome, BlobVisibility, Did,
    Hash, RealmId, SignatureValue, UploadReceipt, canonical,
};
use ed25519_dalek::Signer;
use salvo::http::{Method, StatusCode};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};
use subtle::ConstantTimeEq as _;

use super::{
    append_audit_log, auth_or_render, authenticated_session, is_valid_sha256_digest,
    is_valid_sha256_hex, now, query_param, realm_allows_plaintext_service, realm_has_member,
    render_error, sha256_hex,
};
use crate::error::{AppError, ErrorCode};
use crate::result::{JsonResult, json_ok};
use crate::state::{AppState, BlobRecord, SessionRecord};

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("blob/upload").post(blob_upload))
        .push(Router::with_path("blob/presign").post(blob_presign))
        .push(Router::with_path("blob/get").get(blob_get).head(blob_get))
}

pub(super) fn blob_upload_outcome(
    state: &AppState,
    blob_ref: String,
    size_bytes: u64,
    media_type: String,
    content_digest: String,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<BlobUploadOutcome, AppError> {
    let blob_ref = BlobRef::new(blob_ref)
        .map_err(|error| AppError::internal(format!("blob_ref construction failed: {error}")))?;
    let content_digest = Hash::new(content_digest).map_err(|error| {
        AppError::internal(format!("content_digest construction failed: {error}"))
    })?;
    let issuer_service_did = Did::new(state.config.service_did.clone())
        .map_err(|error| AppError::internal(format!("service DID is invalid: {error}")))?;
    let signing_payload = json!({
        "blob_ref": blob_ref.as_str(),
        "content_digest": content_digest.as_str(),
        "size_bytes": size_bytes,
        "received_at": received_at,
        "issuer_service_did": issuer_service_did.as_str(),
    });
    let canonical_bytes = canonical::canonical_json_bytes(&signing_payload).map_err(|error| {
        AppError::internal(format!("upload receipt canonicalization failed: {error}"))
    })?;
    let signature = state.notary_signing_key().sign(&canonical_bytes);
    let upload_receipt = UploadReceipt {
        blob_ref: blob_ref.clone(),
        content_digest: content_digest.clone(),
        size_bytes,
        received_at,
        issuer_service_did: issuer_service_did.clone(),
        signature: SignatureValue {
            kid: issuer_service_did,
            alg: "EdDSA".to_owned(),
            sig: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    };
    Ok(BlobUploadOutcome {
        blob_ref,
        size_bytes,
        media_type: Some(media_type),
        content_digest,
        upload_receipt: Some(upload_receipt),
    })
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
    let realm_id = match req
        .headers()
        .get("x-cokret-realm-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
    {
        Some(realm_id) => {
            if RealmId::new(realm_id.clone()).is_err() {
                render_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_param",
                    "invalid blob realm_id",
                );
                return;
            }
            if !realm_has_member(state, &realm_id, &session.actor).await {
                render_error(
                    res,
                    StatusCode::FORBIDDEN,
                    "capability_denied",
                    "uploader is not a joined member of the blob Realm",
                );
                return;
            }
            Some(realm_id)
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
    if let Err(message) = enforce_blob_quota(state, &session.actor, realm_id.as_deref(), size).await
    {
        render_error(
            res,
            StatusCode::PAYLOAD_TOO_LARGE,
            "quota_exceeded",
            message,
        );
        return;
    }
    let upload_purpose = match blob_upload_purpose(req) {
        Ok(purpose) => purpose,
        Err(message) => {
            render_error(res, StatusCode::BAD_REQUEST, "invalid_param", message);
            return;
        }
    };
    let mut encryption = match encrypted_attachment_metadata(req) {
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
    if encrypted_flag == Some(true) && encryption.is_none() {
        if let Some(metadata) =
            encrypted_blob_encryption_metadata_for_purpose(upload_purpose.as_deref())
        {
            encryption = Some(metadata);
        }
    }
    let encrypted = encryption.is_some() || encrypted_flag.unwrap_or(false);
    if encrypted_flag == Some(true) && encryption.is_none() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "encrypted blob uploads require x-cokret-attachment-envelope or a supported encrypted x-cokret-blob-purpose",
        );
        return;
    }
    if encrypted_flag == Some(false) && encryption.is_some() {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "x-cokret-blob-encrypted=false conflicts with encrypted attachment metadata",
        );
        return;
    }
    if blob_purpose_requires_encryption(upload_purpose.as_deref()) && !encrypted {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "search index shard uploads must be encrypted",
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
    } else if let Some(realm_id) = realm_id.as_deref() {
        !realm_allows_plaintext_service(state, realm_id).await
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
            crate::metrics::record_digest_mismatch("blob_upload_header");
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
            crate::metrics::record_digest_mismatch("blob_upload_ciphertext_digest");
            render_error(
                res,
                StatusCode::CONFLICT,
                "digest_mismatch",
                "attachment ciphertext_digest does not match blob content",
            );
            return;
        }
    }
    let blob_ref = format!("ck:blob:sha256:{sha256}");
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
    let received_at = now();
    let record = BlobRecord {
        sha256: sha256.clone(),
        size_bytes: size as i64,
        storage_backend: state.object_storage.backend_name().to_owned(),
        storage_key: storage_key.clone(),
        media_type: media_type.clone(),
        filename: filename.clone(),
        realm_id: realm_id.clone(),
        encryption: encryption.clone(),
        legal_hold: false,
        redacted: false,
        visibility: if realm_id.is_some() {
            BlobVisibility::RealmBound
        } else {
            BlobVisibility::Public
        },
        uploaded_by: session.actor,
        created_at: received_at,
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
    let outcome = match blob_upload_outcome(
        state,
        blob_ref,
        size as u64,
        media_type,
        content_digest,
        received_at,
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            render_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                &error.to_string(),
            );
            return;
        }
    };
    res.render(Json(outcome));
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
    let presign_present = query_param(req, "presign").is_some();
    if presign_present
        && req
            .headers()
            .contains_key(salvo::http::header::AUTHORIZATION)
    {
        render_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_param",
            "Authorization and presign are mutually exclusive",
        );
        return;
    }
    let presign_payload = if presign_present {
        match validate_presign_query(state, req, &blob_ref, &purpose) {
            Ok(payload) => Some(payload),
            Err(()) => {
                render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
                return;
            }
        }
    } else {
        None
    };
    let session = if presign_payload.is_some() {
        None
    } else {
        match authenticated_session(state, req).await {
            Ok(session) => Some(session),
            Err(_) => {
                render_error(
                    res,
                    StatusCode::UNAUTHORIZED,
                    "unauthenticated",
                    "missing bearer token",
                );
                return;
            }
        }
    };
    let mut blob = state
        .persistence
        .blobs()
        .get(&blob_ref)
        .await
        .ok()
        .flatten();
    if blob.is_none()
        && purpose == "profile_avatar"
        && let Some(session) = session.as_ref()
    {
        blob = try_recover_profile_avatar_blob(state, &blob_ref, &session.actor).await;
    }
    match blob.as_ref() {
        Some(blob) => {
            if let Some(payload) = presign_payload.as_ref()
                && !presign_payload_matches_blob(blob, payload)
            {
                render_error(res, StatusCode::NOT_FOUND, "not_found", "not found");
                return;
            }
            let denied = if let Some(session) = session.as_ref() {
                !blob_visible_to_session(
                    state,
                    blob,
                    session,
                    query_param(req, "realm_id").as_deref(),
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
            // redacted / actor_private. `/blob/presign` issues a short-lived
            // local direct-serve URL that re-enters this handler without a
            // bearer session; the same gates + response headers apply here.
            let blob_value = presign_blob_policy_value(blob);
            let actor = session
                .as_ref()
                .map(|session| session.actor.as_str())
                .unwrap_or("presigned");
            if let Some(block) = classify_presign_blob_block(&blob_value, actor) {
                let direct_member_e2ee_download =
                    session.is_some() && matches!(block, PresignBlobBlock::E2ee);
                if !direct_member_e2ee_download {
                    let error = block.as_error();
                    render_error(
                        res,
                        error.http_status(),
                        error.wire_code(),
                        error.message.as_str(),
                    );
                    return;
                }
            }
            // Response headers per T11.
            res.headers_mut().insert(
                salvo::http::header::CACHE_CONTROL,
                PRESIGN_CACHE_CONTROL.parse().unwrap(),
            );
            res.headers_mut().insert(
                salvo::http::header::REFERRER_POLICY,
                PRESIGN_REFERRER_POLICY.parse().unwrap(),
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
                format!("sha-256={}", blob_ref.trim_start_matches("ck:blob:sha256:"))
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
                    "realm_id": blob.realm_id.clone(),
                    "presigned": session.is_none(),
                    "status": status.as_u16()
                }),
                "accepted",
            )
            .await;
            if req.method() != Method::HEAD {
                let object_range = match range {
                    Some((start, end)) => start as u64..(end as u64 + 1),
                    None => 0..total_len as u64,
                };
                let stream = match state
                    .object_storage
                    .get_range_stream(&blob.storage_key, object_range)
                    .await
                {
                    Ok(stream) => stream,
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
                res.stream(stream);
            }
        }
        None => render_error(res, StatusCode::NOT_FOUND, "not_found", "not found"),
    }
}

async fn try_recover_profile_avatar_blob(
    state: &AppState,
    blob_ref: &str,
    uploaded_by: &str,
) -> Option<BlobRecord> {
    let sha256 = blob_ref.strip_prefix("ck:blob:sha256:")?;
    if !is_valid_sha256_hex(sha256) {
        return None;
    }
    let storage_key = state.object_storage.object_key_for_sha256(sha256);
    let bytes = match state.object_storage.get(&storage_key).await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::debug!(%error, %blob_ref, %storage_key, "profile avatar blob metadata missing and object is unavailable");
            return None;
        }
    };
    if bytes.len() > MAX_BLOB_UPLOAD_BYTES {
        tracing::warn!(%blob_ref, size = bytes.len(), "refusing to recover oversized profile avatar blob");
        return None;
    }
    let actual_sha256 = sha256_hex(&bytes);
    if actual_sha256 != sha256 {
        tracing::warn!(%blob_ref, %actual_sha256, "refusing to recover profile avatar blob with mismatched digest");
        return None;
    }
    let media_type = infer_profile_avatar_media_type(&bytes)?;
    let record = BlobRecord {
        sha256: sha256.to_owned(),
        size_bytes: bytes.len() as i64,
        storage_backend: state.object_storage.backend_name().to_owned(),
        storage_key,
        media_type,
        filename: None,
        realm_id: None,
        encryption: None,
        legal_hold: false,
        redacted: false,
        visibility: BlobVisibility::Public,
        uploaded_by: uploaded_by.to_owned(),
        created_at: now(),
    };
    if let Err(error) = state.persistence.blobs().put(blob_ref, &record).await {
        tracing::warn!(%error, %blob_ref, "failed to persist recovered profile avatar blob metadata");
        return None;
    }
    Some(record)
}

#[endpoint(
    operation_id = "ck.self.blob.command.presign",
    tags("blob"),
    summary = "Issue a short-lived presigned blob download URL"
)]
#[tracing::instrument(skip_all, fields(op = "ck.self.blob.command.presign"))]
async fn blob_presign(
    aa: crate::routing::system::extract::AuthArgs,
    body: JsonBody<BlobPresignRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<BlobPresignOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let blob_ref = body.blob_ref.as_str();
    let purpose = body.purpose.as_deref().unwrap_or("download");
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
        body.realm_id.as_ref().map(|realm_id| realm_id.as_str()),
    )
    .await
    {
        return Err(AppError::not_found("blob not found"));
    }
    let blob_value = presign_blob_policy_value(&blob);
    if let Some(block) = classify_presign_blob_block(&blob_value, "presigned") {
        return Err(block.as_error());
    }
    let ttl_seconds = u64::from(body.max_age_seconds.unwrap_or(300)).clamp(1, 300);
    let issued_at = now();
    let expires_at = issued_at + chrono::Duration::seconds(ttl_seconds as i64);
    let presign = issue_presign_envelope(
        state,
        blob_ref,
        blob.realm_id.as_deref(),
        purpose,
        &session.actor,
        issued_at,
        expires_at,
    )?;
    let base = state.config.public_base_url.trim_end_matches('/');
    let url = format!(
        "{base}/_cokret/self/blob/get?blob_ref={}&purpose={}&presign={}",
        query_escape(blob_ref),
        query_escape(purpose),
        query_escape(&presign.token),
    );
    json_ok(BlobPresignOutcome {
        url,
        expires_at,
        purpose: Some(purpose.to_owned()),
        realm_id: presign.payload.realm_id,
        nonce: presign.payload.nonce,
        access_scope: presign.payload.access_scope,
    })
}

const BLOB_PRESIGN_SCHEME: &str = "ck.blob.presign.v1";
const BLOB_PRESIGN_PROOF_KIND: &str = "detached_jws";
const BLOB_PRESIGN_PROOF_ALG: &str = "EdDSA";
const BLOB_PRESIGN_KID_FRAGMENT: &str = "notary-key";
const BLOB_PRESIGN_MAX_TTL_SECONDS: i64 = 300;
const BLOB_PRESIGN_CLOCK_SKEW_SECONDS: i64 = 30;

struct IssuedBlobPresign {
    token: String,
    payload: BlobPresignPayload,
}

fn issue_presign_envelope(
    state: &AppState,
    blob_ref: &str,
    realm_id: Option<&str>,
    purpose: &str,
    actor: &str,
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<IssuedBlobPresign, AppError> {
    let issuer_service_did = Did::new(state.config.service_did.clone())
        .map_err(|error| AppError::internal(format!("service DID is invalid: {error}")))?;
    let realm_id = realm_id
        .map(|value| {
            RealmId::new(value.to_owned())
                .map_err(|error| AppError::internal(format!("blob realm_id is invalid: {error}")))
        })
        .transpose()?;
    let audience_hint = Did::new(actor.to_owned()).ok();
    let mut nonce_bytes = [0u8; 16];
    {
        use rand::RngExt;
        rand::rng().fill(&mut nonce_bytes[..]);
    }
    let payload = BlobPresignPayload {
        scheme: BLOB_PRESIGN_SCHEME.to_owned(),
        blob_ref: blob_ref.to_owned(),
        realm_id,
        issuer_service_did: issuer_service_did.clone(),
        issued_at,
        expires_at,
        purpose: purpose.to_owned(),
        nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
        access_scope: BlobPresignAccessScope {
            method: vec!["GET".to_owned(), "HEAD".to_owned()],
            byte_range: None,
        },
        audience_hint,
    };
    let canonical_payload = canonical::canonical_json_bytes(&payload).map_err(|error| {
        AppError::internal(format!(
            "blob presign payload canonicalization failed: {error}"
        ))
    })?;
    let jws =
        cokret_sdk::jws::sign_jws_ed25519(&canonical_payload, state.notary_signing_key().as_ref())
            .map_err(|error| AppError::internal(format!("blob presign signing failed: {error}")))?;
    let envelope = BlobPresignEnvelope {
        payload: payload.clone(),
        proof: BlobPresignDetachedJwsProof {
            kind: BLOB_PRESIGN_PROOF_KIND.to_owned(),
            alg: BLOB_PRESIGN_PROOF_ALG.to_owned(),
            kid: blob_presign_kid(state),
            jws,
        },
    };
    let envelope_bytes = canonical::canonical_json_bytes(&envelope).map_err(|error| {
        AppError::internal(format!(
            "blob presign envelope canonicalization failed: {error}"
        ))
    })?;
    Ok(IssuedBlobPresign {
        token: URL_SAFE_NO_PAD.encode(envelope_bytes),
        payload,
    })
}

fn validate_presign_query(
    state: &AppState,
    req: &Request,
    blob_ref: &str,
    purpose: &str,
) -> Result<BlobPresignPayload, ()> {
    let encoded = query_param(req, "presign").ok_or(())?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| ())?;
    let envelope: BlobPresignEnvelope = serde_json::from_slice(&bytes).map_err(|_| ())?;
    let expected_kid = blob_presign_kid(state);
    if envelope.proof.kind != BLOB_PRESIGN_PROOF_KIND
        || envelope.proof.alg != BLOB_PRESIGN_PROOF_ALG
        || envelope.proof.kid != expected_kid
        || envelope.proof.jws.trim().is_empty()
    {
        return Err(());
    }
    let payload = envelope.payload;
    if payload.scheme != BLOB_PRESIGN_SCHEME
        || payload.blob_ref != blob_ref
        || payload.purpose != purpose
        || payload.issuer_service_did.as_str() != state.config.service_did.as_str()
        || payload.nonce.len() < 16
    {
        return Err(());
    }
    let method = req.method().as_str();
    if payload.access_scope.method.is_empty()
        || payload
            .access_scope
            .method
            .iter()
            .any(|method| method.as_str() != "GET" && method.as_str() != "HEAD")
        || !payload
            .access_scope
            .method
            .iter()
            .any(|allowed| allowed.as_str() == method)
    {
        return Err(());
    }
    let now = now();
    let skew = chrono::Duration::seconds(BLOB_PRESIGN_CLOCK_SKEW_SECONDS);
    if payload.expires_at <= payload.issued_at
        || payload.issued_at - skew > now
        || payload.expires_at + skew < now
        || (payload.expires_at - payload.issued_at).num_seconds() > BLOB_PRESIGN_MAX_TTL_SECONDS
    {
        return Err(());
    }
    let canonical_payload = canonical::canonical_json_bytes(&payload).map_err(|_| ())?;
    let expected_jws =
        cokret_sdk::jws::sign_jws_ed25519(&canonical_payload, state.notary_signing_key().as_ref())
            .map_err(|_| ())?;
    let expected = expected_jws.as_bytes();
    let actual = envelope.proof.jws.as_bytes();
    if expected.len() != actual.len() || !bool::from(expected.ct_eq(actual)) {
        return Err(());
    }
    Ok(payload)
}

fn blob_presign_kid(state: &AppState) -> String {
    format!("{}#{BLOB_PRESIGN_KID_FRAGMENT}", state.config.service_did)
}

fn presign_payload_matches_blob(blob: &BlobRecord, payload: &BlobPresignPayload) -> bool {
    match blob.realm_id.as_deref() {
        Some(realm_id) => payload.realm_id.as_ref().map(|value| value.as_str()) == Some(realm_id),
        None => payload.realm_id.is_none() && blob.visibility == BlobVisibility::Public,
    }
}

fn presign_blob_policy_value(blob: &BlobRecord) -> Value {
    json!({
        "encryption": blob.encryption.clone(),
        "uploaded_by": blob.uploaded_by.clone(),
        "legal_hold": blob.legal_hold,
        "redacted": blob.redacted,
        "visibility": blob.visibility.as_str(),
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
        .get("x-cokret-content-digest")
        .and_then(|value| value.to_str().ok())
    {
        let digest = value.trim();
        if !is_valid_sha256_digest(digest) {
            return Err("x-cokret-content-digest must be sha256:<64 lowercase hex>");
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
            "x-cokret-attachment-envelope",
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

fn blob_upload_purpose(req: &Request) -> Result<Option<String>, &'static str> {
    for header in ["x-cokret-blob-purpose", "x-cokret-purpose"] {
        let Some(value) = req
            .headers()
            .get(header)
            .and_then(|value| value.to_str().ok())
        else {
            continue;
        };
        let purpose = value.trim();
        if purpose.is_empty() {
            return Ok(None);
        }
        if !is_valid_blob_purpose(purpose) {
            return Err("invalid blob upload purpose");
        }
        return Ok(Some(purpose.to_owned()));
    }
    Ok(None)
}

pub(super) const BLOB_PURPOSE_FILE_TRANSFER: &str = "file_transfer";
pub(super) const BLOB_PURPOSE_SEARCH_INDEX_SHARD: &str = "search_index_shard";

pub(super) fn encrypted_blob_encryption_metadata_for_purpose(
    purpose: Option<&str>,
) -> Option<Value> {
    match purpose {
        Some(BLOB_PURPOSE_FILE_TRANSFER) => Some(json!({
            "scheme": "ck.file_transfer.encrypted_blob.v1",
            "purpose": BLOB_PURPOSE_FILE_TRANSFER,
        })),
        Some(BLOB_PURPOSE_SEARCH_INDEX_SHARD) => Some(json!({
            "scheme": "ck.search.encrypted_index_shard.v1",
            "purpose": BLOB_PURPOSE_SEARCH_INDEX_SHARD,
            "profile_id": "ck.profile.search.client_index.v1",
            "data_class": "encrypted_index",
        })),
        _ => None,
    }
}

pub(super) fn blob_purpose_requires_encryption(purpose: Option<&str>) -> bool {
    matches!(purpose, Some(BLOB_PURPOSE_SEARCH_INDEX_SHARD))
}

/// Spec `blob.schema.json#/$defs/encrypted_attachment` carries a `scheme`
/// discriminator. The server stores the envelope as opaque JSON and never
/// decrypts; these constants only drive the light-touch shape validation
/// below (which fields are required), not any cryptographic interpretation.
const SCHEME_WHOLE_FILE: &str = "ck.blob.whole_file_aead.v1";
const SCHEME_STREAM: &str = "ck.blob.stream_aead.v1";

fn validate_encrypted_attachment_metadata(
    metadata: &serde_json::Value,
) -> Result<(), &'static str> {
    let Some(envelope) = metadata.as_object() else {
        return Err("attachment envelope must be a JSON object");
    };

    let has_alg = envelope
        .get("alg")
        .and_then(|value| value.as_str())
        .is_some_and(|value| !value.trim().is_empty());
    if !has_alg {
        return Err("attachment envelope requires alg");
    }

    if !envelope
        .get("key_ref")
        .is_some_and(|value| value.is_object() || value.as_str().is_some())
    {
        return Err("attachment envelope requires key_ref");
    }

    // `ciphertext_digest` is mandatory in both schemes; it is a sha256 of the
    // entire opaque ciphertext (true for whole-file AND stream form), so the
    // server's existing SHA256-of-uploaded-bytes check covers both naturally.
    if !envelope
        .get("ciphertext_digest")
        .and_then(|value| value.as_str())
        .is_some_and(is_valid_sha256_digest)
    {
        return Err("attachment ciphertext_digest must be sha256:<64 lowercase hex>");
    }

    // `scheme` is optional; per spec a missing scheme is treated as
    // `ck.blob.whole_file_aead.v1`. Validate the per-scheme shape only for the
    // two known schemes. Unknown schemes are accepted as opaque JSON (the
    // server does not interpret the envelope) and are NOT subjected to the
    // whole-file `nonce` requirement, so an unknown value is never
    // mis-validated as whole-file.
    match envelope.get("scheme").and_then(|value| value.as_str()) {
        Some(SCHEME_STREAM) => {
            // Streaming chunked AEAD: per-object random `nonce_prefix`, no
            // single `nonce`. Require the stream descriptor fields exist and
            // have the right JSON types; do NOT validate segment structure,
            // nonces, or per-segment tags — that needs the key the server
            // does not hold.
            if envelope
                .get("nonce_prefix")
                .and_then(|value| value.as_str())
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err("stream attachment envelope requires nonce_prefix");
            }
            if !envelope
                .get("segment_size")
                .is_some_and(serde_json::Value::is_u64)
            {
                return Err("stream attachment envelope requires integer segment_size");
            }
            if !envelope
                .get("segment_count")
                .is_some_and(serde_json::Value::is_u64)
            {
                return Err("stream attachment envelope requires integer segment_count");
            }
        }
        None | Some(SCHEME_WHOLE_FILE) => {
            // Whole-file AEAD (explicit or, per spec, the default when scheme
            // is absent): a single `nonce` is required.
            if envelope
                .get("nonce")
                .and_then(|value| value.as_str())
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err("attachment envelope requires nonce");
            }
        }
        Some(_) => {
            // Unknown scheme: forward-compatible passthrough. The server does
            // not interpret the envelope, so store it as-is without imposing
            // either scheme's field requirements.
        }
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

pub(crate) const MAX_BLOB_UPLOAD_BYTES: usize = 10 * 1024 * 1024;
const MAX_BLOB_ACCOUNT_BYTES: usize = 50 * 1024 * 1024;
const MAX_BLOB_REALM_BYTES: usize = 100 * 1024 * 1024;

fn sanitize_media_type(raw: &str) -> Option<String> {
    let media_type = raw.split(';').next()?.trim().to_ascii_lowercase();
    let (top, sub) = media_type.split_once('/')?;
    (is_valid_mime_token(top) && is_valid_mime_token(sub)).then_some(media_type)
}

fn infer_profile_avatar_media_type(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        return Some("image/jpeg".to_owned());
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("image/png".to_owned());
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some("image/gif".to_owned());
    }
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        return Some("image/webp".to_owned());
    }
    None
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
        .get("x-cokret-filename")
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
        .get("x-cokret-blob-encrypted")
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(Some(true)),
        "false" | "0" | "no" => Ok(Some(false)),
        _ => Err("x-cokret-blob-encrypted must be true or false"),
    }
}

pub(super) async fn enforce_blob_quota(
    state: &AppState,
    actor: &str,
    realm_id: Option<&str>,
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
    if let Some(realm_id) = realm_id {
        let realm_bytes: usize = blobs
            .iter()
            .filter(|blob| blob.realm_id.as_deref() == Some(realm_id))
            .map(|blob| blob.size_bytes.max(0) as usize)
            .sum();
        if realm_bytes.saturating_add(size) > MAX_BLOB_REALM_BYTES {
            return Err("realm blob quota exceeded");
        }
    }
    Ok(())
}

pub(super) fn is_valid_blob_purpose(value: &str) -> bool {
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
    requested_realm_id: Option<&str>,
) -> bool {
    if blob.uploaded_by == session.actor {
        return blob.realm_id.as_deref().is_none_or(|realm_id| {
            requested_realm_id.is_none_or(|requested| requested == realm_id)
        });
    }

    let Some(realm_id) = blob.realm_id.as_deref() else {
        return false;
    };
    if requested_realm_id.is_some_and(|requested| requested != realm_id) {
        return false;
    }
    realm_has_member(state, realm_id, &session.actor).await
}

// ────────────────────────────────────────────────────────────────────────
// Presign blob fail-closed gating (spec T11).
// ────────────────────────────────────────────────────────────────────────

/// Blob preflight classifier for presign endpoints. Spec T11.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresignBlobBlock {
    /// Blob payload is end-to-end encrypted; presign would expose key
    /// material — refuse fail-closed.
    E2ee,
    /// Blob is currently subject to a legal hold.
    LegalHold,
    /// Blob has been redacted.
    Redacted,
    /// Blob is actor_private and the requester is not the owner.
    ActorPrivate,
    /// Blob is device_bound and this path has no bound-device verifier.
    DeviceBound,
}

impl PresignBlobBlock {
    pub fn as_error(self) -> AppError {
        match self {
            Self::E2ee => AppError::new(
                ErrorCode::CapabilityDenied,
                "blob is end-to-end encrypted; presign is refused fail-closed",
            ),
            Self::LegalHold => AppError::new(
                ErrorCode::FailedPrecondition,
                "blob is currently subject to a legal hold; presign refused",
            )
            .with_wire_code(crate::error::reasons::LEGAL_HOLD_ACTIVE),
            Self::Redacted => AppError::new(
                ErrorCode::FailedPrecondition,
                "blob has been redacted; presign refused",
            )
            .with_wire_code(crate::error::reasons::BLOB_REDACTED),
            Self::ActorPrivate => AppError::new(
                ErrorCode::CapabilityDenied,
                "blob is actor_private; only the owner may request a presign URL",
            ),
            Self::DeviceBound => AppError::new(
                ErrorCode::CapabilityDenied,
                "blob is device_bound; direct download is refused fail-closed",
            ),
        }
    }
}

/// Inspect a blob record for any of the four fail-closed classes. Spec T11.
/// Returns the matching block reason or `None`.
///
/// The blob record is taken as a JSON value so this fn stays decoupled
/// from `crate::state::BlobRecord`; presign callers pass
/// `serde_json::to_value(&record)` (cheap — BlobRecord is small).
pub fn classify_presign_blob_block(
    blob: &Value,
    requester_actor: &str,
) -> Option<PresignBlobBlock> {
    // E2EE: any encryption metadata present.
    if blob.get("encryption").is_some_and(|v| !v.is_null()) {
        return Some(PresignBlobBlock::E2ee);
    }
    // Legal hold flag.
    if blob.get("legal_hold").and_then(Value::as_bool) == Some(true) {
        return Some(PresignBlobBlock::LegalHold);
    }
    // Redaction.
    if blob.get("redacted").and_then(Value::as_bool) == Some(true) {
        return Some(PresignBlobBlock::Redacted);
    }
    match blob.get("visibility").and_then(Value::as_str) {
        Some("actor_private") => {
            let owner = blob
                .get("uploaded_by")
                .and_then(Value::as_str)
                .unwrap_or("");
            if owner != requester_actor {
                return Some(PresignBlobBlock::ActorPrivate);
            }
        }
        Some("device_bound") => return Some(PresignBlobBlock::DeviceBound),
        _ => {}
    }
    None
}

/// Response headers that MUST be set on presign responses. Spec T11.
///
/// Per spec: presign URLs are short-lived bearer tokens; intermediaries
/// MUST NOT cache them and the referring page MUST NOT leak the URL.
pub const PRESIGN_CACHE_CONTROL: &str = "private, no-store";
pub const PRESIGN_REFERRER_POLICY: &str = "no-referrer";

#[cfg(test)]
mod presign_block_tests {
    use super::*;

    #[test]
    fn presign_blob_e2ee_blocked() {
        let blob = json!({"encryption": {"alg": "xchacha20poly1305"}, "uploaded_by": "did:web:alice.example"});
        assert_eq!(
            classify_presign_blob_block(&blob, "did:web:alice.example"),
            Some(PresignBlobBlock::E2ee)
        );
    }

    #[test]
    fn presign_blob_legal_hold_blocked() {
        let blob = json!({"legal_hold": true, "uploaded_by": "did:web:alice.example"});
        assert_eq!(
            classify_presign_blob_block(&blob, "did:web:alice.example"),
            Some(PresignBlobBlock::LegalHold)
        );
    }

    #[test]
    fn presign_blob_redacted_blocked() {
        let blob = json!({"redacted": true, "uploaded_by": "did:web:alice.example"});
        assert_eq!(
            classify_presign_blob_block(&blob, "did:web:alice.example"),
            Some(PresignBlobBlock::Redacted)
        );
    }

    #[test]
    fn presign_blob_actor_private_blocked_for_non_owner() {
        let blob = json!({"visibility": "actor_private", "uploaded_by": "did:web:alice.example"});
        assert_eq!(
            classify_presign_blob_block(&blob, "did:web:bob.example"),
            Some(PresignBlobBlock::ActorPrivate)
        );
        assert_eq!(
            classify_presign_blob_block(&blob, "did:web:alice.example"),
            None
        );
    }

    #[test]
    fn presign_blob_device_bound_blocked() {
        let blob = json!({"visibility": "device_bound", "uploaded_by": "did:web:alice.example"});
        assert_eq!(
            classify_presign_blob_block(&blob, "did:web:alice.example"),
            Some(PresignBlobBlock::DeviceBound)
        );
    }
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
            realm_id: Some("ck:realm:0196419b-0000-7000-8000-000000000000".to_owned()),
            encryption: None,
            legal_hold: false,
            redacted: false,
            visibility: BlobVisibility::RealmBound,
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

    #[test]
    fn attachment_envelope_whole_file_default_scheme_requires_nonce() {
        let digest = format!("sha256:{}", "0".repeat(64));
        // No scheme → treated as whole_file; nonce present → valid.
        assert!(
            validate_encrypted_attachment_metadata(&json!({
                "alg": "mls_exporter_aead_xchacha20poly1305",
                "key_ref": "ck:mls:exporter",
                "nonce": "AAAAAAAAAAAAAAAA",
                "ciphertext_digest": digest,
            }))
            .is_ok()
        );
        // No scheme, no nonce → rejected.
        assert!(
            validate_encrypted_attachment_metadata(&json!({
                "alg": "mls_exporter_aead_xchacha20poly1305",
                "key_ref": "ck:mls:exporter",
                "ciphertext_digest": digest,
            }))
            .is_err()
        );
    }

    #[test]
    fn attachment_envelope_stream_scheme_requires_stream_descriptor() {
        let digest = format!("sha256:{}", "0".repeat(64));
        // Valid stream envelope: nonce_prefix + segment_size/count, no nonce.
        assert!(
            validate_encrypted_attachment_metadata(&json!({
                "scheme": "ck.blob.stream_aead.v1",
                "alg": "mls_exporter_aead_xchacha20poly1305_stream",
                "key_ref": "ck:mls:exporter",
                "nonce_prefix": "AAAAAAAA",
                "segment_size": 65536,
                "segment_count": 4,
                "ciphertext_digest": digest,
            }))
            .is_ok()
        );
        // Stream scheme but missing nonce_prefix → rejected.
        assert!(
            validate_encrypted_attachment_metadata(&json!({
                "scheme": "ck.blob.stream_aead.v1",
                "alg": "mls_exporter_aead_xchacha20poly1305_stream",
                "key_ref": "ck:mls:exporter",
                "segment_size": 65536,
                "segment_count": 4,
                "ciphertext_digest": digest,
            }))
            .is_err()
        );
        // Stream scheme but segment_size not an integer → rejected.
        assert!(
            validate_encrypted_attachment_metadata(&json!({
                "scheme": "ck.blob.stream_aead.v1",
                "alg": "mls_exporter_aead_xchacha20poly1305_stream",
                "key_ref": "ck:mls:exporter",
                "nonce_prefix": "AAAAAAAA",
                "segment_size": "65536",
                "segment_count": 4,
                "ciphertext_digest": digest,
            }))
            .is_err()
        );
    }

    #[test]
    fn attachment_envelope_unknown_scheme_passes_through_without_nonce() {
        let digest = format!("sha256:{}", "0".repeat(64));
        // Forward-compatible: unknown scheme is accepted opaquely and is NOT
        // forced to carry a whole-file `nonce`.
        assert!(
            validate_encrypted_attachment_metadata(&json!({
                "scheme": "ck.blob.future_scheme.v9",
                "alg": "something-new",
                "key_ref": "ck:mls:exporter",
                "ciphertext_digest": digest,
            }))
            .is_ok()
        );
    }

    #[test]
    fn search_index_shard_purpose_uses_opaque_encrypted_blob_metadata() {
        let metadata =
            encrypted_blob_encryption_metadata_for_purpose(Some(BLOB_PURPOSE_SEARCH_INDEX_SHARD))
                .expect("search shard purpose supported");
        assert_eq!(
            metadata,
            json!({
                "scheme": "ck.search.encrypted_index_shard.v1",
                "purpose": "search_index_shard",
                "profile_id": "ck.profile.search.client_index.v1",
                "data_class": "encrypted_index",
            })
        );
        assert!(blob_purpose_requires_encryption(Some(
            BLOB_PURPOSE_SEARCH_INDEX_SHARD
        )));
        assert!(metadata.get("term").is_none());
        assert!(metadata.get("message_id").is_none());
        assert!(metadata.get("snippet").is_none());
    }

    #[test]
    fn profile_avatar_media_type_inference_accepts_only_safe_image_types() {
        assert_eq!(
            infer_profile_avatar_media_type(&[0xff, 0xd8, 0xff, 0xdb]).as_deref(),
            Some("image/jpeg")
        );
        assert_eq!(
            infer_profile_avatar_media_type(b"\x89PNG\r\n\x1a\nrest").as_deref(),
            Some("image/png")
        );
        assert_eq!(
            infer_profile_avatar_media_type(b"GIF89arest").as_deref(),
            Some("image/gif")
        );
        assert_eq!(
            infer_profile_avatar_media_type(b"RIFF\x00\x00\x00\x00WEBPrest").as_deref(),
            Some("image/webp")
        );
        assert_eq!(infer_profile_avatar_media_type(b"<svg></svg>"), None);
    }
}
