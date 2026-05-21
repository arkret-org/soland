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

/// Pull a single query-string value, decoding `+` to space and any
/// `%XX` percent-escapes back to their raw byte form. Required for
/// typed-id query args like `?space_id=cx:space:...` where browsers
/// (and `encodeURIComponent`) emit `cx%3Aspace%3A...` — without
/// decoding the downstream typed-id validator rejects the literal.
pub fn query_param(req: &Request, key: &str) -> Option<String> {
    req.uri().query().and_then(|query| {
        query.split('&').find_map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (name == key).then(|| percent_decode_query_value(value))
        })
    })
}

fn percent_decode_query_value(value: &str) -> String {
    // Replace `+` → space, then percent-decode bytes. Fall back to the
    // raw value if decoding produces invalid UTF-8 — caller-side
    // validators surface the typed-id error in that case.
    let with_spaces = value.replace('+', " ");
    let bytes = with_spaces.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_digit(bytes[i + 1]);
            let lo = hex_digit(bytes[i + 2]);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or(with_spaces)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

// The repeated-arg form (`?spaces=A&spaces=B`) is what every selector
// path uses; comma-separated values are not standardized.

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
                Some(percent_decode_query_value(value))
            } else {
                None
            }
        })
        .collect()
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

/// Validate a `cx:cursor:<base64url>` token.
///
/// `cx:cursor:` tokens are a base64url-encoded v1 cursor object with
/// `{v,purpose,t,x}` plus either a stateful `h` or stateless `_mac`/`_sig`.
pub fn is_valid_sync_token(token: &str) -> bool {
    let Some(encoded) = token.strip_prefix("cx:cursor:") else {
        return false;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(encoded) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    let has_handle = value.get("h").and_then(|handle| handle.as_str()).is_some();
    let has_mac = value.get("_mac").and_then(|mac| mac.as_str()).is_some();
    let has_sig = value.get("_sig").and_then(|sig| sig.as_str()).is_some();
    value
        .get("v")
        .and_then(|v| v.as_str())
        .is_some_and(|v| v == "1")
        && value
            .get("purpose")
            .and_then(|purpose| purpose.as_str())
            .is_some_and(|purpose| matches!(purpose, "stream" | "barrier"))
        && value.get("t").and_then(|t| t.as_str()).is_some()
        && value
            .get("x")
            .and_then(|x| x.as_i64())
            .is_some_and(|x| x > 0)
        && ((has_handle && !has_mac && !has_sig) || (!has_handle && (has_mac || has_sig)))
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
// (The `entity` abstraction never landed in `contrix-spec/v1`; typed
// objects in the protocol are `cx:space:` / `cx:flow:` / `cx:morph:` /
// `cx:relation:` / `cx:view:`, each driven by its own dedicated event
// kind.)

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
