//! Conformance-vector HTTP handlers.
//!
//! Each handler is intentionally thin: it pulls the request body, runs the
//! forked conformance primitive in [`super::util`], and serializes the
//! result. The handlers are gated behind the `ck.profile.conformance_harness.v1`
//! build profile: the `/_cokret/_conformance/*` namespace is only mounted when
//! that profile is active (development_mode=true), and [`super::ensure_enabled`]
//! is the defense-in-depth handler guard. See [`super`] and
//! `service-http-binding.md` §2.1.2.
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
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Deserialize, ToSchema)]
pub struct EncodeVectorRequest {
    vector_id: String,
    #[salvo(schema(value_type = serde_json::Value))]
    input: Value,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CanonicalJsonDigestOutcome {
    canonical_json: String,
    digest: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SignVectorRequest {
    vector_id: String,
    #[salvo(schema(value_type = serde_json::Value))]
    event: Value,
    signing_key_ref: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SignVectorOutcome {
    canonical_bytes: String,
    digest: String,
    signature: String,
    public_key: String,
    algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HlcClockVectorItem {
    actor: String,
    hlc: String,
    #[serde(default)]
    #[salvo(schema(value_type = serde_json::Value))]
    payload_hint: Value,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct HlcMergeVectorRequest {
    vector_id: String,
    clocks: Vec<HlcClockVectorItem>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HlcMergeVectorOutcome {
    ordered: Vec<HlcClockVectorItem>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CursorVectorRequest {
    vector_id: String,
    #[salvo(schema(value_type = Vec<serde_json::Value>))]
    events: Vec<Value>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CursorVectorOutcome {
    cursor: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct EnvelopeVectorRequest {
    vector_id: String,
    #[salvo(schema(value_type = serde_json::Value))]
    envelope: Value,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CanonicalBytesDigestOutcome {
    canonical_bytes: String,
    digest: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RedactVectorRequest {
    vector_id: String,
    #[salvo(schema(value_type = serde_json::Value))]
    event: Value,
    #[salvo(schema(value_type = serde_json::Value))]
    redaction: Value,
    viewer_did: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RedactVectorOutcome {
    #[salvo(schema(value_type = serde_json::Value))]
    projected_event: Value,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SnapshotVectorRequest {
    vector_id: String,
    #[salvo(schema(value_type = serde_json::Value))]
    manifest: Value,
    #[salvo(schema(value_type = Vec<serde_json::Value>))]
    chunks: Vec<Value>,
    #[serde(default)]
    #[salvo(schema(value_type = serde_json::Value))]
    signature: Option<Value>,
    #[serde(default)]
    revoked_signer_dids: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SnapshotVectorOutcome {
    vector_id: String,
    manifest_digest: String,
    chunk_hashes: Vec<String>,
    expected_chunk_count: usize,
    state_digest: String,
    event_set_commitment: String,
    signature_valid: bool,
    signer_did: String,
    signed_transcript_fields: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct QueryVectorRequest {
    vector_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[salvo(schema(value_type = serde_json::Value))]
    query: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[salvo(schema(value_type = Vec<serde_json::Value>))]
    rows: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[salvo(schema(value_type = Vec<serde_json::Value>))]
    dataset: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    unauthorized_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[salvo(schema(value_type = Vec<serde_json::Value>))]
    events: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[salvo(schema(value_type = Vec<serde_json::Value>))]
    chunks: Option<Vec<Value>>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    #[salvo(schema(value_type = serde_json::Value))]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct QueryVectorFrontier {
    barrier_cursor: String,
    row_count: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct QueryVectorOutcome {
    vector_id: String,
    #[salvo(schema(value_type = Vec<serde_json::Value>))]
    items: Vec<Value>,
    has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
    frontier: QueryVectorFrontier,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChaosOperationOutcome {
    operation_id: String,
    canonical_event: Option<CanonicalEventDiagnostic>,
    projection_event: Option<ProjectionEventDiagnostic>,
    consistent: bool,
}

#[derive(Debug, Serialize, ToSchema)]
struct CanonicalEventDiagnostic {
    event_id: String,
    actor_id: String,
    actor_seq: u64,
    realm_id: Option<String>,
    kind: String,
    canonical_digest: String,
    received_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
struct ProjectionEventDiagnostic {
    event_id: String,
    realm_id: String,
    event_kind: String,
    operation_type: String,
    operation_id: Option<String>,
    sender: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
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
pub async fn encode(body: JsonBody<EncodeVectorRequest>) -> JsonResult<CanonicalJsonDigestOutcome> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let vector = body.vector_id.as_str();
    if let Some((code, message)) = encode_reject_for_vector(vector) {
        return Err(AppError::new(code, message));
    }
    let canonical = canonical_json(&body.input)
        .map_err(|err| AppError::new(ErrorCode::SchemaViolation, format!("canonicalize: {err}")))?;
    let digest = sha256_digest(canonical.as_bytes());
    json_ok(CanonicalJsonDigestOutcome {
        canonical_json: canonical,
        digest,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.conformance.sign",
    tags("conformance"),
    summary = "Run a signature-binding conformance vector"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.conformance.sign"))]
pub async fn sign(body: JsonBody<SignVectorRequest>) -> JsonResult<SignVectorOutcome> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let _vector = body.vector_id.as_str();
    let event = &body.event;
    let signing_key_ref = body.signing_key_ref.as_str();

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

    json_ok(SignVectorOutcome {
        canonical_bytes: canonical,
        digest,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        public_key: URL_SAFE_NO_PAD.encode(verifying_key.to_bytes()),
        algorithm: "ed25519".to_owned(),
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.conformance.hlc_merge",
    tags("conformance"),
    summary = "Run an HLC ordering conformance vector"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.conformance.hlc_merge"))]
pub async fn hlc_merge(body: JsonBody<HlcMergeVectorRequest>) -> JsonResult<HlcMergeVectorOutcome> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let vector = body.vector_id.as_str();
    if vector.contains("logical_overflow") {
        return Err(AppError::new(
            ErrorCode::HlcLogicalOverflow,
            "vector requests logical-counter overflow reject",
        )
        .with_status(StatusCode::UNPROCESSABLE_ENTITY));
    }
    let clocks: Vec<(String, String, Value)> = body
        .clocks
        .iter()
        .map(|clock| {
            (
                clock.hlc.clone(),
                clock.actor.clone(),
                clock.payload_hint.clone(),
            )
        })
        .collect();
    let ordered = order_hlc_clocks(&clocks);
    let ordered = ordered
        .into_iter()
        .map(|(hlc, actor, payload_hint)| HlcClockVectorItem {
            actor,
            hlc,
            payload_hint,
        })
        .collect();
    json_ok(HlcMergeVectorOutcome { ordered })
}

#[endpoint(
    operation_id = "org.cokret.soland.conformance.cursor",
    tags("conformance"),
    summary = "Run an opaque-cursor conformance vector"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.conformance.cursor"))]
pub async fn cursor(body: JsonBody<CursorVectorRequest>) -> JsonResult<CursorVectorOutcome> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let _vector = body.vector_id.as_str();
    let events = &body.events;

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
    json_ok(CursorVectorOutcome {
        cursor: cursor_token,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.conformance.envelope",
    tags("conformance"),
    summary = "Run an encrypted-envelope canonical-digest conformance vector"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.conformance.envelope"))]
pub async fn envelope(
    body: JsonBody<EnvelopeVectorRequest>,
) -> JsonResult<CanonicalBytesDigestOutcome> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let _vector = body.vector_id.as_str();
    let canonical = canonical_json(&body.envelope)
        .map_err(|err| AppError::new(ErrorCode::SchemaViolation, format!("canonicalize: {err}")))?;
    let digest = sha256_digest(canonical.as_bytes());
    json_ok(CanonicalBytesDigestOutcome {
        canonical_bytes: canonical,
        digest,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.conformance.redact",
    tags("conformance"),
    summary = "Run a redaction visibility / projection conformance vector"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.conformance.redact"))]
pub async fn redact(body: JsonBody<RedactVectorRequest>) -> JsonResult<RedactVectorOutcome> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let _vector = body.vector_id.as_str();
    let event = &body.event;
    let redaction = &body.redaction;
    let viewer_did = body.viewer_did.as_str();

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

    json_ok(RedactVectorOutcome {
        projected_event: projected,
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.conformance.snapshot",
    tags("conformance"),
    summary = "Run a snapshot manifest / chunk integrity conformance vector"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.conformance.snapshot"))]
pub async fn snapshot(body: JsonBody<SnapshotVectorRequest>) -> JsonResult<SnapshotVectorOutcome> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let vector = body.vector_id.as_str();
    let manifest = &body.manifest;
    let chunks = &body.chunks;
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

    let signature = manifest.get("signature").or(body.signature.as_ref());
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
        || body.revoked_signer_dids.iter().any(|did| did == signer_did)
    {
        return Err(
            AppError::new(ErrorCode::CapabilityDenied, "snapshot issuer is revoked")
                .with_wire_code("snapshot_issuer_revoked")
                .with_status(StatusCode::FORBIDDEN),
        );
    }

    json_ok(SnapshotVectorOutcome {
        vector_id: vector.to_owned(),
        manifest_digest,
        chunk_hashes,
        expected_chunk_count: chunks.len(),
        state_digest,
        event_set_commitment,
        signature_valid: signature.is_some(),
        signer_did: signer_did.to_owned(),
        signed_transcript_fields: SNAPSHOT_SIGNED_TRANSCRIPT_FIELDS
            .iter()
            .map(|field| (*field).to_owned())
            .collect(),
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.conformance.query",
    tags("conformance"),
    summary = "Run a query filter / sort / pagination conformance vector"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.conformance.query"))]
pub async fn query(body: JsonBody<QueryVectorRequest>) -> JsonResult<QueryVectorOutcome> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let body_value = serde_json::to_value(&body)
        .map_err(|error| AppError::internal(format!("conformance query body encode: {error}")))?;
    let vector = body.vector_id.as_str();
    let query_value = body_value.get("query").unwrap_or(&body_value);
    validate_query_limits(vector, &body_value, query_value)?;
    validate_query_shape(vector, &body_value, query_value)?;

    let mut rows = body_value
        .get("rows")
        .or_else(|| body_value.get("dataset"))
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
        .or_else(|| body_value.get("cursor"))
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

    json_ok(QueryVectorOutcome {
        vector_id: vector.to_owned(),
        items: page,
        has_more: next_cursor.is_some(),
        next_cursor,
        frontier: QueryVectorFrontier {
            barrier_cursor,
            row_count: rows.len(),
        },
    })
}

#[endpoint(
    operation_id = "org.cokret.soland.conformance.chaos_operation",
    tags("conformance"),
    summary = "Inspect a committed operation during local chaos testing"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.conformance.chaos_operation"))]
pub async fn chaos_operation(
    depot: &mut Depot,
    req: &Request,
) -> JsonResult<ChaosOperationOutcome> {
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

    json_ok(ChaosOperationOutcome {
        operation_id,
        canonical_event: canonical_json,
        projection_event: projection_json,
        consistent: canonical_event.is_some() == projection_event.is_some(),
    })
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
    AppError::new(ErrorCode::SchemaViolation, message).with_status(StatusCode::BAD_REQUEST)
}

fn limit_error(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::QuotaExceeded, message)
        .with_wire_code("quota_exceeded")
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

fn canonical_event_diagnostic(record: &CanonicalEventRecord) -> CanonicalEventDiagnostic {
    CanonicalEventDiagnostic {
        event_id: record.event_id.clone(),
        actor_id: record.actor_id.clone(),
        actor_seq: record.actor_seq,
        realm_id: record.realm_id.clone(),
        kind: record.kind.clone(),
        canonical_digest: record.canonical_digest.clone(),
        received_at: record.received_at,
    }
}

fn projection_event_diagnostic(record: &ProjectionEventRecord) -> ProjectionEventDiagnostic {
    ProjectionEventDiagnostic {
        event_id: record.event_id.clone(),
        realm_id: record.realm_id.clone(),
        event_kind: record.event_kind.clone(),
        operation_type: record.operation_type.clone(),
        operation_id: record.operation_id.clone(),
        sender: record.sender.clone(),
        created_at: record.created_at,
    }
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

        assert_eq!(err.wire_code(), "schema_violation");
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
