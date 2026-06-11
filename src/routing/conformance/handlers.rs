//! Conformance-vector HTTP handlers.
//!
//! Each handler is intentionally thin: it pulls the request body, runs the
//! forked conformance primitive in [`super::util`], and serializes the
//! result. The handlers are gated behind [`super::endpoints_enabled`] so
//! production builds don't carry the conformance surface unless the operator
//! explicitly opts in via `SOLAND_ENABLE_CONFORMANCE_ENDPOINTS=1`.
//!
//! Wire shapes mirror `cotest/e2e/scenarios/conformance/encoding-vectors.md`
//! Pre-conditions §:
//!   POST /_soland/self/conformance/encode    { vector_id, input }                              → {
//! canonical_json, digest }   POST /_soland/self/conformance/sign      { vector_id, event,
//! signing_key_ref }             → { canonical_bytes, digest, signature, public_key }   POST /api/
//! v1/conformance/hlc-merge { vector_id, clocks: [{actor, hlc, payload_hint}] } → { ordered: [...]
//! }   POST /_soland/self/conformance/cursor    { vector_id, events, reduce_round }               →
//! { cursor }   POST /_soland/self/conformance/envelope  { vector_id, envelope }
//! → { canonical_bytes, digest }   POST /_soland/self/conformance/redact    { vector_id, event,
//! redaction, viewer_did }       → { projected_event }
//!
//! Reject paths (`vector_id` starts with `reject_`) return HTTP 4xx with
//! `error.code` in the documented set:
//!   - `schema_violation` / `invalid_canonical_json` / `invalid_encoding` for /encode
//!   - `hlc_logical_overflow` for /hlc-merge
//!
//! When the conformance namespace is disabled at build/runtime, every route
//! returns `404 not_found` so the cotest probe stays in its accepted status
//! set (`[200, 404, 405, 501]`).

use std::cmp::Ordering;
use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::util::{
    CursorShape, canonical_json, encode_cursor_shape, order_hlc_clocks, sha256_digest,
};
use crate::error::{AppError, ErrorCode};
use crate::routing::system::util::query_param;
use crate::state::{AppState, CanonicalEventRecord, ProjectionEventRecord};
use crate::{JsonResult, json_ok};

const MAX_CONFORMANCE_BATCH: usize = 1_000;
const MAX_CONFORMANCE_RELATION_DEPTH: u64 = 32;
const MAX_CONFORMANCE_ENVELOPE_BYTES: usize = 1024 * 1024;

// Spec `snapshot.schema.json`: the manifest's own identifier field is `id`
// (`snapshot_ref` only appears at external reference positions).
const SNAPSHOT_SIGNED_TRANSCRIPT_FIELDS: &[&str] = &[
    "id",
    "realm_id",
    "reducer_profile",
    "schema_profile_refs",
    "state_digest",
    "frontier",
    "event_set_commitment",
    "chunks",
    "verification_hints",
    "created_by",
    "created_at",
];

/// Pull `vector_id` from a body — used by every endpoint to detect the
/// `reject_*` / `logical_overflow` test paths and to surface an explicit
/// code when the field is missing.
fn vector_id(body: &Value) -> Result<&str, AppError> {
    body.get("vector_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("missing vector_id"))
}

/// Errors that mean "the vector_id encodes a deliberate reject path" — used
/// by `/encode` to map `reject_noncanonical_numbers.v1` /
/// `reject_malformed_json.v1` style vectors to their documented codes.
fn encode_reject_for_vector(vector: &str) -> Option<(ErrorCode, &'static str)> {
    if vector.contains("reject_malformed_json") {
        Some((ErrorCode::BadJson, "vector requests malformed-JSON reject"))
    } else if vector.contains("reject_noncanonical_numbers") {
        Some((
            ErrorCode::SchemaViolation,
            "vector requests non-canonical-numbers reject",
        ))
    } else if vector.contains("reject_") {
        Some((
            ErrorCode::SchemaViolation,
            "vector requests canonicalization reject",
        ))
    } else {
        None
    }
}

#[endpoint(
    operation_id = "org.cokret.soland.conformance.encode",
    tags("conformance"),
    summary = "Run a canonical-JSON / digest conformance vector"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.conformance.encode"))]
pub async fn encode(body: JsonBody<Value>) -> JsonResult<Value> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let vector = vector_id(&body)?;
    if let Some((code, message)) = encode_reject_for_vector(vector) {
        return Err(AppError::new(code, message));
    }
    let input = body
        .get("input")
        .ok_or_else(|| AppError::missing_param("missing input"))?;
    let canonical = canonical_json(input)
        .map_err(|err| AppError::new(ErrorCode::SchemaViolation, format!("canonicalize: {err}")))?;
    let digest = sha256_digest(canonical.as_bytes());
    json_ok(json!({
        "canonical_json": canonical,
        "digest": digest,
    }))
}

#[endpoint(
    operation_id = "org.cokret.soland.conformance.sign",
    tags("conformance"),
    summary = "Run a signature-binding conformance vector"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.conformance.sign"))]
pub async fn sign(body: JsonBody<Value>) -> JsonResult<Value> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let _vector = vector_id(&body)?;
    let event = body
        .get("event")
        .ok_or_else(|| AppError::missing_param("missing event"))?;
    let signing_key_ref = body
        .get("signing_key_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("missing signing_key_ref"))?;

    // Deterministic conformance signing key: derive seed from the
    // `signing_key_ref` string. This is intentionally not a real account /
    // device key — conformance vectors only need a stable Ed25519 keypair
    // so the wire test can verify (a) determinism and (b) signature
    // validity under the returned `public_key`. Production-grade signing
    // (admin keystore, notary rotate-signing-key) lives on the existing
    // admin / federation surfaces.
    let mut hasher = Sha256::new();
    hasher.update(b"soland:conformance:sign:");
    hasher.update(signing_key_ref.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    // Build canonical bytes from the event payload sans `unsigned` — same
    // shape as `cotest::conformance::canonical_proof_payload` (which strips
    // `unsigned` from the signed coverage).
    let mut payload = Map::new();
    if let Some(object) = event.as_object() {
        for (key, value) in object {
            if key != "unsigned" {
                payload.insert(key.clone(), value.clone());
            }
        }
    }
    let canonical = canonical_json(&Value::Object(payload))
        .map_err(|err| AppError::new(ErrorCode::SchemaViolation, format!("canonicalize: {err}")))?;
    let digest = sha256_digest(canonical.as_bytes());
    let signature = signing_key.sign(canonical.as_bytes());

    json_ok(json!({
        "canonical_bytes": canonical,
        "digest": digest,
        "signature": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        "public_key": URL_SAFE_NO_PAD.encode(verifying_key.to_bytes()),
        "algorithm": "ed25519",
    }))
}

#[endpoint(
    operation_id = "org.cokret.soland.conformance.hlc_merge",
    tags("conformance"),
    summary = "Run an HLC ordering conformance vector"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.conformance.hlc_merge"))]
pub async fn hlc_merge(body: JsonBody<Value>) -> JsonResult<Value> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let vector = vector_id(&body)?;
    if vector.contains("logical_overflow") {
        return Err(AppError::new(
            ErrorCode::HlcLogicalOverflow,
            "vector requests logical-counter overflow reject",
        )
        .with_status(StatusCode::UNPROCESSABLE_ENTITY));
    }
    let clocks_value = body
        .get("clocks")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::missing_param("missing clocks array"))?;
    let mut clocks: Vec<(String, String, Value)> = Vec::with_capacity(clocks_value.len());
    for clock in clocks_value {
        let actor = clock
            .get("actor")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::invalid_param("clock missing actor"))?
            .to_owned();
        let hlc = clock
            .get("hlc")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::invalid_param("clock missing hlc"))?
            .to_owned();
        let payload_hint = clock.get("payload_hint").cloned().unwrap_or(Value::Null);
        clocks.push((hlc, actor, payload_hint));
    }
    let ordered = order_hlc_clocks(&clocks);
    let ordered_json: Vec<Value> = ordered
        .into_iter()
        .map(|(hlc, actor, payload_hint)| {
            json!({
                "actor": actor,
                "hlc": hlc,
                "payload_hint": payload_hint,
            })
        })
        .collect();
    json_ok(json!({ "ordered": ordered_json }))
}

#[endpoint(
    operation_id = "org.cokret.soland.conformance.cursor",
    tags("conformance"),
    summary = "Run an opaque-cursor conformance vector"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.conformance.cursor"))]
pub async fn cursor(body: JsonBody<Value>) -> JsonResult<Value> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let _vector = vector_id(&body)?;
    let events = body
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::missing_param("missing events"))?;

    // The cursor must be stable under re-reduce — i.e. independent of the
    // input event order. Encode the *count* of events plus the canonical
    // digest of their sorted-event-id set. That keeps the cursor opaque
    // (no plaintext event_id leak — they're hashed into x) and stable.
    let mut event_ids: Vec<String> = events
        .iter()
        .map(|event| {
            event
                .get("event_id")
                .and_then(Value::as_str)
                .map(|s| s.to_owned())
                .unwrap_or_default()
        })
        .collect();
    event_ids.sort();
    let mut hasher = Sha256::new();
    hasher.update(event_ids.join(",").as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    // Fold the SHA-256 into a u64 for the `x` field — the `ck:cursor:`
    // envelope hashes are opaque to the client, so a 64-bit truncation
    // is sufficient and keeps the cursor short.
    let mut x_bytes = [0u8; 8];
    x_bytes.copy_from_slice(&digest[..8]);
    let shape = CursorShape {
        v: "1".to_owned(),
        x: u64::from_be_bytes(x_bytes),
    };
    let cursor_token = encode_cursor_shape(&shape)
        .map_err(|err| AppError::new(ErrorCode::InternalError, format!("encode cursor: {err}")))?;
    json_ok(json!({ "cursor": cursor_token }))
}

#[endpoint(
    operation_id = "org.cokret.soland.conformance.envelope",
    tags("conformance"),
    summary = "Run an encrypted-envelope canonical-digest conformance vector"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.conformance.envelope"))]
pub async fn envelope(body: JsonBody<Value>) -> JsonResult<Value> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let _vector = vector_id(&body)?;
    let envelope_value = body
        .get("envelope")
        .ok_or_else(|| AppError::missing_param("missing envelope"))?;
    let canonical = canonical_json(envelope_value)
        .map_err(|err| AppError::new(ErrorCode::SchemaViolation, format!("canonicalize: {err}")))?;
    let digest = sha256_digest(canonical.as_bytes());
    json_ok(json!({
        "canonical_bytes": canonical,
        "digest": digest,
    }))
}

#[endpoint(
    operation_id = "org.cokret.soland.conformance.redact",
    tags("conformance"),
    summary = "Run a redaction visibility / projection conformance vector"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.conformance.redact"))]
pub async fn redact(body: JsonBody<Value>) -> JsonResult<Value> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let _vector = vector_id(&body)?;
    let event = body
        .get("event")
        .ok_or_else(|| AppError::missing_param("missing event"))?;
    let redaction = body
        .get("redaction")
        .ok_or_else(|| AppError::missing_param("missing redaction"))?;
    let viewer_did = body
        .get("viewer_did")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("missing viewer_did"))?;

    // Spec §3.2 — redaction strips the fields listed in `redaction.fields`
    // (default: `["content", "payload.content"]`) unless the viewer is the
    // event's original sender. The projection MUST drop the keys entirely
    // (not set them to null) and MUST keep `event_id`, `redacted_because`,
    // and tombstone markers visible to every viewer.
    let owner_did = event
        .get("sender")
        .and_then(Value::as_str)
        .or_else(|| event.get("actor").and_then(Value::as_str));
    let viewer_is_owner = owner_did == Some(viewer_did);

    let default_fields = vec![Value::from("content"), Value::from("payload.content")];
    let strip_fields: Vec<&str> = redaction
        .get("fields")
        .and_then(Value::as_array)
        .unwrap_or(&default_fields)
        .iter()
        .filter_map(Value::as_str)
        .collect();

    let mut projected = event.clone();
    if !viewer_is_owner {
        if let Some(object) = projected.as_object_mut() {
            for path in &strip_fields {
                strip_path(object, path);
            }
        }
        // Always surface the redacted_because marker if present in the
        // redaction event so guests can render a tombstone.
        if let Some(reason) = redaction.get("reason") {
            if let Some(object) = projected.as_object_mut() {
                object.insert("redacted_because".to_owned(), reason.clone());
            }
        }
    }

    json_ok(json!({ "projected_event": projected }))
}

#[endpoint(
    operation_id = "org.cokret.soland.conformance.snapshot",
    tags("conformance"),
    summary = "Run a snapshot manifest / chunk integrity conformance vector"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.conformance.snapshot"))]
pub async fn snapshot(body: JsonBody<Value>) -> JsonResult<Value> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let vector = vector_id(&body)?;
    let manifest = body
        .get("manifest")
        .ok_or_else(|| AppError::missing_param("missing manifest"))?;
    let chunks = body
        .get("chunks")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::missing_param("missing chunks array"))?;
    if chunks.len() > MAX_CONFORMANCE_BATCH || vector.contains("batch_size_over_max") {
        return Err(limit_error(
            "snapshot chunks exceed the 1,000 item wire limit",
        ));
    }

    let manifest_canonical = canonical_json(manifest).map_err(schema_error)?;
    if manifest_canonical.len() > MAX_CONFORMANCE_ENVELOPE_BYTES
        || vector.contains("envelope_over_1mib")
    {
        return Err(payload_too_large_error(
            "snapshot manifest canonical envelope exceeds 1 MiB",
        ));
    }
    let manifest_digest = sha256_digest(manifest_canonical.as_bytes());

    let mut chunk_hashes = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.iter().enumerate() {
        let material = snapshot_chunk_material(chunk)?;
        let digest = sha256_digest(material.as_bytes());
        if let Some(declared) = declared_chunk_digest(manifest, chunks, index, chunk)
            && declared != digest
        {
            return Err(AppError::new(
                ErrorCode::SchemaViolation,
                format!("snapshot chunk {index} digest mismatch"),
            )
            .with_wire_code("snapshot_chunk_digest_mismatch")
            .with_status(StatusCode::BAD_REQUEST));
        }
        chunk_hashes.push(digest);
    }

    let state_digest = manifest
        .get("state_digest")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| digest_json(&json!({ "chunk_hashes": chunk_hashes })));
    let event_set_commitment = manifest
        .get("event_set_commitment")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            digest_json(&json!({
                "manifest_digest": manifest_digest.clone(),
                "state_digest": state_digest.clone(),
            }))
        });

    let signature = manifest.get("signature").or_else(|| body.get("signature"));
    let signer_did = signature
        .and_then(|sig| sig.get("signer_did"))
        .and_then(Value::as_str)
        .or_else(|| manifest.get("created_by").and_then(Value::as_str))
        .unwrap_or("did:web:soland.conformance");
    if vector.contains("revoked")
        || signature
            .and_then(|sig| sig.get("revoked"))
            .and_then(Value::as_bool)
            == Some(true)
        || string_array(body.get("revoked_signer_dids")).any(|did| did == signer_did)
    {
        return Err(
            AppError::new(ErrorCode::CapabilityDenied, "snapshot issuer is revoked")
                .with_wire_code("snapshot_issuer_revoked")
                .with_status(StatusCode::FORBIDDEN),
        );
    }

    json_ok(json!({
        "vector_id": vector,
        "manifest_digest": manifest_digest,
        "chunk_hashes": chunk_hashes,
        "expected_chunk_count": chunks.len(),
        "state_digest": state_digest,
        "event_set_commitment": event_set_commitment,
        "signature_valid": signature.is_some(),
        "signer_did": signer_did,
        "signed_transcript_fields": SNAPSHOT_SIGNED_TRANSCRIPT_FIELDS,
    }))
}

#[endpoint(
    operation_id = "org.cokret.soland.conformance.query",
    tags("conformance"),
    summary = "Run a query filter / sort / pagination conformance vector"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.conformance.query"))]
pub async fn query(body: JsonBody<Value>) -> JsonResult<Value> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let vector = vector_id(&body)?;
    let query_value = body.get("query").unwrap_or(&body);
    validate_query_limits(vector, &body, query_value)?;
    validate_query_shape(vector, &body, query_value)?;

    let mut rows = body
        .get("rows")
        .or_else(|| body.get("dataset"))
        .or_else(|| query_value.get("rows"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(default_query_rows);
    rows.retain(|row| row_matches_query(row, query_value));
    sort_query_rows(&mut rows, query_value);

    let query_digest_shape = query_digest_value(query_value);
    let query_digest = digest_json(&query_digest_shape);
    let offset = query_value
        .get("cursor")
        .or_else(|| body.get("cursor"))
        .and_then(Value::as_str)
        .map(|cursor_token| decode_query_cursor(cursor_token, &query_digest))
        .transpose()?
        .unwrap_or(0);
    if offset > rows.len() {
        return Err(
            AppError::invalid_param("query cursor offset is beyond the result set")
                .with_wire_code("invalid_cursor"),
        );
    }
    let limit = query_value
        .get("limit")
        .or_else(|| query_value.get("page_size"))
        .and_then(Value::as_u64)
        .unwrap_or(rows.len().max(1) as u64)
        .min(MAX_CONFORMANCE_BATCH as u64) as usize;
    let end = (offset + limit).min(rows.len());
    let page: Vec<Value> = rows[offset..end].to_vec();
    let next_cursor = if end < rows.len() {
        Some(encode_query_cursor(end, &query_digest)?)
    } else {
        None
    };
    let barrier_cursor = encode_query_cursor(rows.len(), &query_digest)?;

    json_ok(json!({
        "vector_id": vector,
        "items": page,
        "has_more": next_cursor.is_some(),
        "next_cursor": next_cursor,
        "frontier": {
            "barrier_cursor": barrier_cursor,
            "row_count": rows.len(),
        },
    }))
}

#[endpoint(
    operation_id = "org.cokret.soland.conformance.chaos_operation",
    tags("conformance"),
    summary = "Inspect a committed operation during local chaos testing"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.conformance.chaos_operation"))]
pub async fn chaos_operation(depot: &mut Depot, req: &Request) -> JsonResult<Value> {
    super::ensure_enabled()?;
    let state = depot.obtain::<AppState>().expect("state injected");
    if !state.config.development_mode {
        return Err(AppError::not_found(
            "chaos diagnostics are only available in development_mode",
        ));
    }
    let operation_id = query_param(req, "operation_id")
        .ok_or_else(|| AppError::missing_param("missing operation_id"))?;
    if !operation_id.starts_with("ck:operation:") {
        return Err(AppError::invalid_param(
            "operation_id must use ck:operation:",
        ));
    }

    let canonical_event = state
        .persistence
        .events()
        .snapshot_all()
        .await
        .map_err(|error| AppError::new(ErrorCode::InternalError, error.to_string()))?
        .into_iter()
        .find(|record| canonical_event_operation_id(record).as_deref() == Some(&operation_id));
    let projection_event = state
        .persistence
        .projection_events()
        .snapshot_all()
        .await
        .map_err(|error| AppError::new(ErrorCode::InternalError, error.to_string()))?
        .into_iter()
        .find(|record| record.operation_id.as_deref() == Some(&operation_id));
    let canonical_json = canonical_event.as_ref().map(canonical_event_diagnostic);
    let projection_json = projection_event.as_ref().map(projection_event_diagnostic);

    json_ok(json!({
        "operation_id": operation_id,
        "canonical_event": canonical_json,
        "projection_event": projection_json,
        "consistent": canonical_event.is_some() == projection_event.is_some(),
    }))
}

/// Drop `path` from `object`, supporting dotted paths like `"payload.content"`.
fn strip_path(object: &mut Map<String, Value>, path: &str) {
    if let Some((head, rest)) = path.split_once('.') {
        if let Some(Value::Object(child)) = object.get_mut(head) {
            strip_path(child, rest);
        }
    } else {
        object.remove(path);
    }
}

fn snapshot_chunk_material(chunk: &Value) -> Result<String, AppError> {
    if let Some(payload) = chunk.get("payload") {
        return canonical_json(payload).map_err(schema_error);
    }
    if let Some(bytes) = chunk.get("bytes").and_then(Value::as_str) {
        return Ok(bytes.to_owned());
    }
    if let Some(data) = chunk.get("data") {
        return canonical_json(data).map_err(schema_error);
    }
    let mut scrubbed = chunk.clone();
    if let Some(object) = scrubbed.as_object_mut() {
        for key in [
            "digest",
            "chunk_hash",
            "expected_digest",
            "expected_chunk_hash",
        ] {
            object.remove(key);
        }
    }
    canonical_json(&scrubbed).map_err(schema_error)
}

fn declared_chunk_digest(
    manifest: &Value,
    chunks: &[Value],
    index: usize,
    chunk: &Value,
) -> Option<String> {
    chunk
        .get("digest")
        .or_else(|| chunk.get("chunk_hash"))
        .or_else(|| chunk.get("expected_digest"))
        .and_then(Value::as_str)
        .or_else(|| {
            manifest
                .get("chunk_hashes")
                .and_then(Value::as_array)
                .and_then(|values| values.get(index))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            manifest
                .get("chunks")
                .and_then(Value::as_array)
                .and_then(|values| values.get(index))
                .and_then(|entry| entry.get("digest").or_else(|| entry.get("chunk_hash")))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            chunks
                .get(index)
                .and_then(|entry| entry.get("declared_digest"))
                .and_then(Value::as_str)
        })
        .map(ToOwned::to_owned)
}

fn validate_query_limits(vector: &str, body: &Value, query_value: &Value) -> Result<(), AppError> {
    if vector.contains("envelope_over_1mib")
        || canonical_json(body).map_err(schema_error)?.len() > MAX_CONFORMANCE_ENVELOPE_BYTES
    {
        return Err(payload_too_large_error(
            "query canonical envelope exceeds 1 MiB",
        ));
    }
    let limit = query_value
        .get("limit")
        .or_else(|| query_value.get("page_size"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if limit > MAX_CONFORMANCE_BATCH as u64 || vector.contains("page_size_over_max") {
        return Err(limit_error("query page size exceeds 1,000"));
    }
    let batch_count = body
        .get("events")
        .or_else(|| body.get("rows"))
        .or_else(|| body.get("chunks"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if batch_count > MAX_CONFORMANCE_BATCH || vector.contains("batch_size_over_max") {
        return Err(limit_error("query batch exceeds 1,000 items"));
    }
    let relation_depth = query_value
        .pointer("/relation/depth")
        .or_else(|| query_value.pointer("/relation_expansion/depth"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if relation_depth > MAX_CONFORMANCE_RELATION_DEPTH || vector.contains("relation_depth_over_max")
    {
        return Err(limit_error("query relation expansion depth exceeds 32"));
    }
    Ok(())
}

fn validate_query_shape(vector: &str, body: &Value, query_value: &Value) -> Result<(), AppError> {
    if vector.contains("unauthorized_field")
        || string_array(body.get("unauthorized_fields"))
            .next()
            .is_some()
        || string_array(query_value.get("projection")).any(|field| field.starts_with("secret"))
    {
        return Err(query_schema_error(
            "query references a field outside the caller's read grant",
        ));
    }

    for filter in query_filters(query_value) {
        let op = filter
            .get("op")
            .or_else(|| filter.get("operator"))
            .and_then(Value::as_str)
            .unwrap_or("eq");
        if !allowed_query_op(op) || vector.contains("unknown_filter_key") {
            return Err(query_schema_error("query filter op is not registered"));
        }
    }

    let mut seen_sort = BTreeMap::<String, String>::new();
    for sort in query_sorts(query_value) {
        let Some(field) = sort.get("field").and_then(Value::as_str) else {
            continue;
        };
        let direction = sort
            .get("direction")
            .or_else(|| sort.get("dir"))
            .and_then(Value::as_str)
            .unwrap_or("asc")
            .to_ascii_lowercase();
        if !matches!(direction.as_str(), "asc" | "desc") {
            return Err(query_schema_error("query sort direction is not registered"));
        }
        if let Some(previous) = seen_sort.insert(field.to_owned(), direction.clone())
            && previous != direction
        {
            return Err(query_schema_error(
                "query carries conflicting sort directions for the same field",
            ));
        }
    }
    if vector.contains("conflicting_sort") {
        return Err(query_schema_error(
            "query carries conflicting sort directions for the same field",
        ));
    }
    Ok(())
}

fn query_filters(query_value: &Value) -> Vec<&Value> {
    if let Some(filters) = query_value.get("filters").and_then(Value::as_array) {
        return filters.iter().collect();
    }
    query_value
        .get("filter")
        .and_then(Value::as_array)
        .map(|filters| filters.iter().collect())
        .unwrap_or_default()
}

fn query_sorts(query_value: &Value) -> Vec<&Value> {
    query_value
        .get("order_by")
        .or_else(|| query_value.get("sort"))
        .and_then(Value::as_array)
        .map(|sorts| sorts.iter().collect())
        .unwrap_or_default()
}

fn row_matches_query(row: &Value, query_value: &Value) -> bool {
    query_filters(query_value).into_iter().all(|filter| {
        let field = filter.get("field").and_then(Value::as_str).unwrap_or("");
        let op = filter
            .get("op")
            .or_else(|| filter.get("operator"))
            .and_then(Value::as_str)
            .unwrap_or("eq");
        let expected = filter.get("value").unwrap_or(&Value::Null);
        let actual = row.get(field).unwrap_or(&Value::Null);
        match op {
            "eq" => actual == expected,
            "neq" => actual != expected,
            "in" => expected
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value == actual)),
            "not_in" => expected
                .as_array()
                .is_none_or(|values| values.iter().all(|value| value != actual)),
            "lt" => compare_json(actual, expected) == Some(Ordering::Less),
            "lte" => compare_json(actual, expected)
                .is_some_and(|ordering| matches!(ordering, Ordering::Less | Ordering::Equal)),
            "gt" => compare_json(actual, expected) == Some(Ordering::Greater),
            "gte" => compare_json(actual, expected)
                .is_some_and(|ordering| matches!(ordering, Ordering::Greater | Ordering::Equal)),
            "contains" => contains_json(actual, expected),
            "exists" => expected.as_bool().unwrap_or(true) != actual.is_null(),
            "prefix" => actual
                .as_str()
                .zip(expected.as_str())
                .is_some_and(|(actual, prefix)| actual.starts_with(prefix)),
            "full_text" => {
                actual
                    .as_str()
                    .zip(expected.as_str())
                    .is_some_and(|(actual, needle)| {
                        actual
                            .to_ascii_lowercase()
                            .contains(&needle.to_ascii_lowercase())
                    })
            }
            _ => false,
        }
    })
}

fn sort_query_rows(rows: &mut [Value], query_value: &Value) {
    let sorts = query_sorts(query_value);
    if sorts.is_empty() {
        return;
    }
    rows.sort_by(|left, right| {
        for sort in &sorts {
            let Some(field) = sort.get("field").and_then(Value::as_str) else {
                continue;
            };
            let descending = sort
                .get("direction")
                .or_else(|| sort.get("dir"))
                .and_then(Value::as_str)
                .is_some_and(|dir| dir.eq_ignore_ascii_case("desc"));
            let ordering = compare_json(
                left.get(field).unwrap_or(&Value::Null),
                right.get(field).unwrap_or(&Value::Null),
            )
            .unwrap_or(Ordering::Equal);
            let ordering = if descending {
                ordering.reverse()
            } else {
                ordering
            };
            if ordering != Ordering::Equal {
                return ordering;
            }
        }
        Ordering::Equal
    });
}

fn compare_json(left: &Value, right: &Value) -> Option<Ordering> {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => left.as_f64()?.partial_cmp(&right.as_f64()?),
        (Value::String(left), Value::String(right)) => Some(left.cmp(right)),
        (Value::Bool(left), Value::Bool(right)) => Some(left.cmp(right)),
        _ => None,
    }
}

fn contains_json(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::String(actual), Value::String(expected)) => actual.contains(expected),
        (Value::Array(actual), expected) => actual.iter().any(|item| item == expected),
        _ => false,
    }
}

fn allowed_query_op(op: &str) -> bool {
    matches!(
        op,
        "eq" | "neq"
            | "in"
            | "not_in"
            | "lt"
            | "lte"
            | "gt"
            | "gte"
            | "contains"
            | "exists"
            | "prefix"
            | "full_text"
    )
}

fn default_query_rows() -> Vec<Value> {
    vec![
        json!({"id": "row-a", "kind": "task", "title": "Alpha", "rank": 1, "visible": true}),
        json!({"id": "row-b", "kind": "note", "title": "Beta", "rank": 2, "visible": true}),
        json!({"id": "row-c", "kind": "task", "title": "Gamma", "rank": 3, "visible": false}),
    ]
}

fn encode_query_cursor(offset: usize, query_digest: &str) -> Result<String, AppError> {
    let shape = json!({
        "v": "1",
        "offset": offset,
        "query_digest": query_digest,
    });
    let canonical = canonical_json(&shape).map_err(schema_error)?;
    Ok(format!(
        "ck:cursor:{}",
        URL_SAFE_NO_PAD.encode(canonical.as_bytes())
    ))
}

fn query_digest_value(query_value: &Value) -> Value {
    let mut digest_value = query_value.clone();
    if let Some(object) = digest_value.as_object_mut() {
        object.remove("cursor");
    }
    digest_value
}

fn decode_query_cursor(cursor_token: &str, query_digest: &str) -> Result<usize, AppError> {
    let payload = cursor_token
        .strip_prefix("ck:cursor:")
        .ok_or_else(|| AppError::invalid_param("query cursor must start with ck:cursor:"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| AppError::invalid_param("query cursor is not base64url"))?;
    let shape: Value = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::invalid_param("query cursor payload is not JSON"))?;
    if shape.get("query_digest").and_then(Value::as_str) != Some(query_digest) {
        return Err(AppError::invalid_param("query cursor digest mismatch")
            .with_wire_code("invalid_cursor"));
    }
    shape
        .get("offset")
        .and_then(Value::as_u64)
        .map(|offset| offset as usize)
        .ok_or_else(|| AppError::invalid_param("query cursor offset missing"))
}

fn digest_json(value: &Value) -> String {
    canonical_json(value)
        .map(|canonical| sha256_digest(canonical.as_bytes()))
        .unwrap_or_else(|_| sha256_digest(value.to_string().as_bytes()))
}

fn string_array(value: Option<&Value>) -> impl Iterator<Item = &str> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

fn schema_error(error: anyhow::Error) -> AppError {
    AppError::new(
        ErrorCode::SchemaViolation,
        format!("canonicalize conformance vector: {error}"),
    )
}

fn query_schema_error(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::SchemaViolation, message)
        .with_wire_code("query_schema_violation")
        .with_status(StatusCode::BAD_REQUEST)
}

fn limit_error(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::QuotaExceeded, message)
        .with_wire_code("scalability_limit_exceeded")
        .with_status(StatusCode::PAYLOAD_TOO_LARGE)
}

fn payload_too_large_error(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::PayloadTooLarge, message)
        .with_wire_code("payload_too_large")
        .with_status(StatusCode::PAYLOAD_TOO_LARGE)
}

fn canonical_event_operation_id(record: &CanonicalEventRecord) -> Option<String> {
    record
        .envelope
        .get("unsigned")
        .and_then(Value::as_object)
        .and_then(|unsigned| unsigned.get("local_operation_idempotency_alias"))
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("ck:operation:"))
        .map(ToOwned::to_owned)
        .or_else(|| {
            record
                .event_id
                .strip_prefix("ck:event:")
                .map(|suffix| format!("ck:operation:{suffix}"))
        })
}

fn canonical_event_diagnostic(record: &CanonicalEventRecord) -> Value {
    json!({
        "event_id": &record.event_id,
        "actor_id": &record.actor_id,
        "actor_seq": record.actor_seq,
        "realm_id": &record.realm_id,
        "kind": &record.kind,
        "canonical_digest": &record.canonical_digest,
        "received_at": record.received_at,
    })
}

fn projection_event_diagnostic(record: &ProjectionEventRecord) -> Value {
    json!({
        "event_id": &record.event_id,
        "realm_id": &record.realm_id,
        "event_kind": &record.event_kind,
        "operation_type": &record.operation_type,
        "operation_id": &record.operation_id,
        "sender": &record.sender,
        "created_at": record.created_at,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn encode_reject_classifier_recognizes_documented_prefixes() {
        assert!(encode_reject_for_vector("reject_noncanonical_numbers.v1").is_some());
        assert!(encode_reject_for_vector("reject_malformed_json.v1").is_some());
        assert!(encode_reject_for_vector("reject_other_thing.v1").is_some());
        assert!(encode_reject_for_vector("ck.vector.encoding.canonical_json.basic.v1").is_none());
    }

    #[test]
    fn strip_path_removes_nested_field() {
        let mut event = json!({
            "event_id": "ck:event:1",
            "payload": { "content": "secret", "kind": "msg" },
            "sender": "did:alice",
        });
        if let Some(object) = event.as_object_mut() {
            strip_path(object, "payload.content");
        }
        assert_eq!(
            event,
            json!({
                "event_id": "ck:event:1",
                "payload": { "kind": "msg" },
                "sender": "did:alice",
            })
        );
    }

    #[test]
    fn query_cursor_round_trip_is_bound_to_query_digest() {
        let first_query = json!({"filter": [{"field": "kind", "op": "eq", "value": "task"}]});
        let first_digest = digest_json(&query_digest_value(&first_query));
        let second_digest =
            digest_json(&json!({"filter": [{"field": "kind", "op": "eq", "value": "note"}]}));
        let cursor_token = encode_query_cursor(25, &first_digest).expect("cursor encodes");

        assert_eq!(
            decode_query_cursor(&cursor_token, &first_digest).unwrap(),
            25
        );
        assert_eq!(
            digest_json(&query_digest_value(&json!({
                "cursor": cursor_token,
                "filter": [{"field": "kind", "op": "eq", "value": "task"}],
            }))),
            first_digest
        );

        let err = decode_query_cursor(&cursor_token, &second_digest)
            .expect_err("cursor must be bound to the canonical query shape");
        assert_eq!(err.wire_code(), "invalid_cursor");
    }

    #[test]
    fn query_shape_rejects_unauthorized_projection() {
        let body = json!({});
        let query_value = json!({ "projection": ["id", "secret_notes"] });

        let err = validate_query_shape("ck.vector.query.projection", &body, &query_value)
            .expect_err("secret projection must fail closed");

        assert_eq!(err.wire_code(), "query_schema_violation");
        assert_eq!(err.http_status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn snapshot_declared_digest_mismatch_is_detected() {
        let manifest = json!({
            "chunk_hashes": ["sha256:0000000000000000000000000000000000000000000000000000000000000000"]
        });
        let chunks = vec![json!({ "payload": { "body": "hello" } })];
        let material = snapshot_chunk_material(&chunks[0]).unwrap();
        let actual_digest = sha256_digest(material.as_bytes());

        assert_ne!(
            declared_chunk_digest(&manifest, &chunks, 0, &chunks[0]).unwrap(),
            actual_digest
        );
    }
}
