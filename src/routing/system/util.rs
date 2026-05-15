//! Shared mechanical helpers used across every handler module.
//!
//! Anything in here MUST be:
//! - free of `AppState` access (no locks, no persistence reads),
//! - free of business logic (no decision-making about events / authz / sync),
//! - and reusable across at least two domains.
//!
//! Domain-specific helpers (`auth_or_render`, `append_audit_log`,
//! `space_has_member`, the blob/MIME helpers, the proof verifiers, etc.) stay
//! in their owning module so they can carry their own invariants. They will
//! land here only if they outgrow that scope.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use contrix_sdk::{DeviceId, Did, SpaceId};
use salvo::http::{StatusCode, header};
use salvo::prelude::*;
use sha2::{Digest, Sha256};

use crate::ids;
use crate::wire::{ApiError, ApiErrorDetail};

// ── HTTP helpers ────────────────────────────────────────────────────────────

/// Render a Contrix-shaped error envelope and stamp the response status.
///
/// Produces the flat Matrix/Palpo-style envelope:
/// `{"ok": false, "error": {"errcode": <code>, "error": <message>,
///  "request_id": <opaque>}}` — aligning with how downstream clients
/// (sodmin, yougen, cotest) read errors via `body.error.errcode` /
/// `body.error.error`.
pub fn render_error(res: &mut Response, status: StatusCode, code: &str, message: &str) {
    let request_id = ids::generate_request_id();
    res.status_code(status);
    res.render(Json(ApiError {
        ok: false,
        error: ApiErrorDetail {
            errcode: code.to_owned(),
            error: message.to_owned(),
            request_id,
            retry_after_ms: None,
            details: std::collections::BTreeMap::new(),
        },
    }));
}

/// Pull a single query-string value, decoding `+` to space.
pub fn query_param(req: &Request, key: &str) -> Option<String> {
    req.uri().query().and_then(|query| {
        query.split('&').find_map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (name == key).then(|| value.replace('+', " "))
        })
    })
}

// `query_list` removed in round 7 — never called. The repeated-arg form
// (`?spaces=A&spaces=B`) is what every selector path uses; comma-separated
// values were never standardized.

/// Pull **every** occurrence of `key` from the query string as repeated args
/// (e.g. `?spaces=A&spaces=B&spaces=C`) — required for spec C17
/// `cx.events.query` / `cx.events.subscribe` selectors which accept
/// `spaces[]` ∪ `actors[]`. `+` decoded to space; empty values dropped.
pub fn query_param_all(req: &Request, key: &str) -> Vec<String> {
    let Some(query) = req.uri().query() else {
        return Vec::new();
    };
    query
        .split('&')
        .filter_map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            if name == key && !value.is_empty() {
                Some(value.replace('+', " "))
            } else {
                None
            }
        })
        .collect()
}

/// Treat the query value `1 / true / yes` as a boolean true; anything else is false.
pub fn query_flag(req: &Request, key: &str) -> bool {
    query_param(req, key)
        .as_deref()
        .is_some_and(|value| matches!(value, "1" | "true" | "yes"))
}

/// Extract the `Bearer ...` token from the `Authorization` header.
pub fn bearer_token(req: &Request) -> Option<&str> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

// ── Crypto helpers ──────────────────────────────────────────────────────────

/// Hex-encoded SHA-256 of `bytes` (lowercase, 64 chars).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

// ── Token / digest validators ───────────────────────────────────────────────

/// Validate a `sx:<unix_millis>` or `cx:cursor:<base64url>` token.
///
/// `cx:cursor:` tokens are a base64url-encoded JSON object that must declare
/// `schema = cx.schema.cursor.v1`, `version = 1`, a positive `issued_at_ms`,
/// and a `positions` object.
pub fn is_valid_sync_token(token: &str) -> bool {
    if let Some(millis) = token.strip_prefix("sx:") {
        return millis.parse::<i64>().is_ok_and(|value| value > 0);
    }
    let Some(encoded) = token.strip_prefix("cx:cursor:") else {
        return false;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(encoded) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    value
        .get("schema")
        .and_then(|schema| schema.as_str())
        .is_some_and(|schema| schema == "cx.schema.cursor.v1")
        && value
            .get("version")
            .and_then(|version| version.as_u64())
            .is_some_and(|version| version == 1)
        && value
            .get("issued_at_ms")
            .and_then(|millis| millis.as_i64())
            .is_some_and(|millis| millis > 0)
        && value
            .get("positions")
            .is_some_and(|positions| positions.is_object())
}

/// `sha256:<64 lowercase hex>` shape.
pub fn is_valid_sha256_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(is_valid_sha256_hex)
}

/// 64 lowercase hex characters.
pub fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
}

// ── Identifier / handle validators ──────────────────────────────────────────

/// Wrap `Did::new` and discard the SDK error, since callers always answer with
/// `bad_request / invalid_param` regardless of the underlying reason.
pub fn validate_did(value: &str) -> Result<Did, ()> {
    Did::new(value.to_owned()).map_err(|_| ())
}

pub fn validate_device_id(value: &str) -> Result<DeviceId, ()> {
    DeviceId::new(value.to_owned()).map_err(|_| ())
}

pub fn validate_space_id(value: &str) -> Result<SpaceId, ()> {
    SpaceId::new(value.to_owned()).map_err(|_| ())
}

/// `@`-prefixed, lowercase, alphanumeric + `-_.` only.
pub fn is_valid_handle(handle: &str) -> bool {
    let normalized = normalize_handle(handle);
    normalized.len() > 1
        && normalized
            .trim_start_matches('@')
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Lowercase + ensure leading `@`.
pub fn normalize_handle(handle: &str) -> String {
    let trimmed = handle.trim().to_ascii_lowercase();
    if trimmed.starts_with('@') {
        trimmed
    } else {
        format!("@{trimmed}")
    }
}

/// Best-effort `@<tail>` derived from the last DID label, with `.` → `-`.
pub fn handle_for_did(did: &str) -> String {
    did.rsplit(':')
        .next()
        .map(|tail| format!("@{}", tail.replace('.', "-")))
        .unwrap_or_else(|| "@user".to_owned())
}

// ── Discoverability validator ───────────────────────────────────────────────
//
// (`is_valid_entity_type` / `is_supported_cx_entity_type` were removed in
// round 6 — the `entity` abstraction never landed in `contrix-spec/v1`; typed
// objects in the protocol are `cx:flow:` / `cx:place:` / `cx:morph:` /
// `cx:relation:` / `cx:view:`, each driven by its own dedicated event kind.)

/// Allow-list of space-discoverability values.
pub fn is_valid_discoverability(value: &str) -> bool {
    matches!(
        value,
        "public" | "listed" | "restricted" | "unlisted" | "invite_only" | "secret"
    )
}

// ── Misc JSON helpers ───────────────────────────────────────────────────────

/// `serde_json::Number`s come back as either i64 or u64 depending on sign /
/// magnitude. Either is integer-shaped for our purposes.
pub fn is_json_integer(value: &serde_json::Value) -> bool {
    value.as_i64().is_some() || value.as_u64().is_some()
}
