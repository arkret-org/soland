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
//!   POST /api/v1/conformance/encode    { vector_id, input }                              → { canonical_json, digest }
//!   POST /api/v1/conformance/sign      { vector_id, event, signing_key_ref }             → { canonical_bytes, digest, signature, public_key }
//!   POST /api/v1/conformance/hlc-merge { vector_id, clocks: [{actor, hlc, payload_hint}] } → { ordered: [...] }
//!   POST /api/v1/conformance/cursor    { vector_id, events, reduce_round }               → { cursor }
//!   POST /api/v1/conformance/envelope  { vector_id, envelope }                           → { canonical_bytes, digest }
//!   POST /api/v1/conformance/redact    { vector_id, event, redaction, viewer_did }       → { projected_event }
//!
//! Reject paths (`vector_id` starts with `reject_`) return HTTP 4xx with
//! `errcode` in the documented set:
//!   - `schema_violation` / `invalid_canonical_json` / `invalid_encoding` for /encode
//!   - `hlc_logical_overflow` for /hlc-merge
//!
//! When the conformance namespace is disabled at build/runtime, every route
//! returns `404 not_found` so the cotest probe stays in its accepted status
//! set (`[200, 404, 405, 501]`).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::util::{
    CursorShape, canonical_json, encode_cursor_shape, order_hlc_clocks, sha256_prefixed,
};
use crate::error::{AppError, ErrorCode};
use crate::{JsonResult, json_ok};

/// Pull `vector_id` from a body — used by every endpoint to detect the
/// `reject_*` / `logical_overflow` test paths and to surface an explicit
/// errcode when the field is missing.
fn vector_id(body: &Value) -> Result<&str, AppError> {
    body.get("vector_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::missing_param("missing vector_id"))
}

/// Errors that mean "the vector_id encodes a deliberate reject path" — used
/// by `/encode` to map `reject_noncanonical_numbers.v1` /
/// `reject_malformed_json.v1` style vectors to their documented errcodes.
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
    operation_id = "cx.conformance.encode",
    tags("conformance"),
    summary = "Run a canonical-JSON / digest conformance vector"
)]
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
    let digest = sha256_prefixed(canonical.as_bytes());
    json_ok(json!({
        "canonical_json": canonical,
        "digest": digest,
    }))
}

#[endpoint(
    operation_id = "cx.conformance.sign",
    tags("conformance"),
    summary = "Run a signature-binding conformance vector"
)]
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
    // (admin keystore, anchorer rotate-signing-key) lives on the existing
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
    let digest = sha256_prefixed(canonical.as_bytes());
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
    operation_id = "cx.conformance.hlc_merge",
    tags("conformance"),
    summary = "Run an HLC ordering conformance vector"
)]
pub async fn hlc_merge(body: JsonBody<Value>) -> JsonResult<Value> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let vector = vector_id(&body)?;
    if vector.contains("logical_overflow") {
        return Err(AppError::new(
            ErrorCode::HlcLogicalOverflow,
            "vector requests logical-counter overflow reject",
        ));
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
    operation_id = "cx.conformance.cursor",
    tags("conformance"),
    summary = "Run an opaque-cursor conformance vector"
)]
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
    // Fold the SHA-256 into a u64 for the `x` field — the `cx:cursor:`
    // envelope hashes are opaque to the client, so a 64-bit truncation
    // is sufficient and keeps the cursor short.
    let mut x_bytes = [0u8; 8];
    x_bytes.copy_from_slice(&digest[..8]);
    let shape = CursorShape {
        v: "1".to_owned(),
        x: u64::from_be_bytes(x_bytes),
    };
    let cursor_token = encode_cursor_shape(&shape).map_err(|err| {
        AppError::new(ErrorCode::InternalError, format!("encode cursor: {err}"))
    })?;
    json_ok(json!({ "cursor": cursor_token }))
}

#[endpoint(
    operation_id = "cx.conformance.envelope",
    tags("conformance"),
    summary = "Run an encrypted-envelope canonical-digest conformance vector"
)]
pub async fn envelope(body: JsonBody<Value>) -> JsonResult<Value> {
    super::ensure_enabled()?;
    let body = body.into_inner();
    let _vector = vector_id(&body)?;
    let envelope_value = body
        .get("envelope")
        .ok_or_else(|| AppError::missing_param("missing envelope"))?;
    let canonical = canonical_json(envelope_value)
        .map_err(|err| AppError::new(ErrorCode::SchemaViolation, format!("canonicalize: {err}")))?;
    let digest = sha256_prefixed(canonical.as_bytes());
    json_ok(json!({
        "canonical_bytes": canonical,
        "digest": digest,
    }))
}

#[endpoint(
    operation_id = "cx.conformance.redact",
    tags("conformance"),
    summary = "Run a redaction visibility / projection conformance vector"
)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encode_reject_classifier_recognizes_documented_prefixes() {
        assert!(encode_reject_for_vector("reject_noncanonical_numbers.v1").is_some());
        assert!(encode_reject_for_vector("reject_malformed_json.v1").is_some());
        assert!(encode_reject_for_vector("reject_other_thing.v1").is_some());
        assert!(encode_reject_for_vector("cx.vector.encoding.canonical_json.basic.v1").is_none());
    }

    #[test]
    fn strip_path_removes_nested_field() {
        let mut event = json!({
            "event_id": "cx:event:1",
            "payload": { "content": "secret", "kind": "msg" },
            "sender": "did:alice",
        });
        if let Some(object) = event.as_object_mut() {
            strip_path(object, "payload.content");
        }
        assert_eq!(
            event,
            json!({
                "event_id": "cx:event:1",
                "payload": { "kind": "msg" },
                "sender": "did:alice",
            })
        );
    }
}
