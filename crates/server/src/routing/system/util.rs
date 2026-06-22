//! Shared mechanical helpers used across every handler module.
//!
//! Anything in here MUST be:
//! - free of `AppState` access (no locks, no persistence reads),
//! - free of business logic (no decision-making about events / authz / sync),
//! - and reusable across at least two domains.
//!
//! Domain-specific helpers (`auth_or_render`, `append_audit_log`,
//! `realm_has_member`, the blob/MIME helpers, the proof verifiers, etc.) stay
//! in their owning module so they can carry their own invariants. They will
//! land here only if they outgrow that scope.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cokret_sdk::{DeviceId, Did, RealmId, SpaceId};
use salvo::http::{StatusCode, header};
use salvo::prelude::*;

use crate::ids;
// ── HTTP helpers ────────────────────────────────────────────────────────────

/// Render a Cokret-shaped error envelope and stamp the response status.
///
/// Produces the spec-canonical SDK envelope:
/// `{"ok": false, "error": {"code": <code>, "message": <message>},
///  "request_id": <opaque>}`.
pub fn render_error(res: &mut Response, status: StatusCode, code: &str, message: &str) {
    let request_id = ids::generate_request_id();
    res.status_code(status);
    res.render(Json(
        cokret_sdk::ErrorEnvelope::new(code, message).with_request_id(request_id),
    ));
}

/// Variant of [`render_error`] that also stamps a free-form
/// `error.details.reason_detail` diagnostic.
///
/// Round 2 — used by `AppError::with_reason_detail` to thread an
/// unstable diagnostic string through the otherwise canonical
/// envelope. Clients MUST NOT parse this value; the OpenAPI
/// description on every error response notes the contract.
pub fn render_error_with_detail(
    res: &mut Response,
    status: StatusCode,
    code: &str,
    message: &str,
    reason_detail: &str,
) {
    let request_id = ids::generate_request_id();
    res.status_code(status);
    res.render(Json(
        cokret_sdk::ErrorEnvelope::new(code, message)
            .with_request_id(request_id)
            .with_detail(
                "reason_detail",
                serde_json::Value::String(reason_detail.to_owned()),
            ),
    ));
}

/// Variant of [`render_error`] that stamps a **stable** top-level `reason`
/// discriminator (and `error.reason` mirror) alongside the canonical envelope.
///
/// COT-03-001 / `applet-integration.md` §7.3.1: the inbound transaction-push
/// signature failures pin the discriminator in `reason`, keeping `error.code`
/// the generic `unauthenticated`. The discriminator is mirrored at both the
/// top level (`reason`) and `error.reason` so callers can read either. An
/// optional `reason_detail` is still threaded into `error.details.reason_detail`
/// for opaque diagnostics.
pub fn render_error_with_top_level_reason(
    res: &mut Response,
    status: StatusCode,
    code: &str,
    message: &str,
    reason: &str,
    reason_detail: Option<&str>,
) {
    let request_id = ids::generate_request_id();
    let mut envelope = cokret_sdk::ErrorEnvelope::new(code, message).with_request_id(request_id);
    if let Some(reason_detail) = reason_detail {
        envelope = envelope.with_detail(
            "reason_detail",
            serde_json::Value::String(reason_detail.to_owned()),
        );
    }
    let mut body = serde_json::to_value(&envelope).unwrap_or_else(|_| {
        serde_json::json!({
            "ok": false,
            "error": { "code": code, "message": message },
        })
    });
    if let Some(object) = body.as_object_mut() {
        object.insert(
            "reason".to_owned(),
            serde_json::Value::String(reason.to_owned()),
        );
        if let Some(error) = object
            .get_mut("error")
            .and_then(serde_json::Value::as_object_mut)
        {
            error.insert(
                "reason".to_owned(),
                serde_json::Value::String(reason.to_owned()),
            );
        }
    }
    res.status_code(status);
    res.render(Json(body));
}

/// Pull a single query-string value, decoding `+` to space and any
/// `%XX` percent-escapes back to their raw byte form. Required for
/// typed-id query args like `?space_id=ck:space:...` where browsers
/// (and `encodeURIComponent`) emit `ck%3Aspace%3A...` — without
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

// The repeated-arg form (`?realms=A&realms=B`) is what every selector
// path uses; comma-separated values are not standardized.

/// Pull **every** occurrence of `key` from the query string as repeated args
/// (e.g. `?realms=A&realms=B&realms=C`) — required for spec C17
/// `ck.self.events.query.scan` / `ck.self.events.stream.subscribe` selectors which accept
/// `realms[]` ∪ `actors[]`. `+` decoded to space; empty values dropped.
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
///
/// Thin re-export of the SDK [`cokret_sdk::canonical::sha256_hex`] so soland
/// shares the single canonical hash primitive instead of a local
/// reimplementation.
pub fn sha256_hex(bytes: &[u8]) -> String {
    cokret_sdk::canonical::sha256_hex(bytes)
}

// ── Token / digest validators ───────────────────────────────────────────────

/// Validate a `ck:cursor:<base64url>` token.
///
/// `ck:cursor:` tokens are a base64url-encoded v1 cursor object with
/// `{v,purpose,t,x,h}`. Core cursors do not carry inline positions or
/// stateless integrity material.
pub fn is_valid_sync_token(token: &str) -> bool {
    let Some(encoded) = token.strip_prefix("ck:cursor:") else {
        return false;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(encoded) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    let Some(handle) = value.get("h").and_then(|handle| handle.as_str()) else {
        return false;
    };
    if value.get("_mac").is_some()
        || value.get("_sig").is_some()
        || value.get("issuer_kid").is_some()
        || value.get("_ctx").is_some()
        || value.get("_positions").is_some()
        || value.get("_filter_digest").is_some()
        || value.get("filter_digest").is_some()
    {
        return false;
    }
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
        && crate::routing::events::sync::validate_cursor_handle(handle).is_ok()
}

/// `sha256:<64 lowercase hex>` shape.
pub fn is_valid_sha256_digest(value: &str) -> bool {
    value.starts_with("sha256:") && cokret_sdk::Hash::new(value.to_owned()).is_ok()
}

/// Active `<digest-suite>:<64 lowercase hex>` hash shape.
pub fn is_valid_hash_digest(value: &str) -> bool {
    cokret_sdk::Hash::new(value.to_owned()).is_ok()
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

pub fn validate_realm_id(value: &str) -> Result<RealmId, ()> {
    RealmId::new(value.to_owned()).map_err(|_| ())
}

pub fn validate_space_id(value: &str) -> Result<SpaceId, ()> {
    SpaceId::new(value.to_owned()).map_err(|_| ())
}

/// `@`-prefixed, lowercase, alphanumeric + `-_.` only.
///
/// CKP R3 spec-sync (2026-05-27, cokret-spec b47ff6ec): the wire-level
/// canonical comparison MUST run through NFC + UTS#39 confusable folding +
/// script-mix rejection. We delegate that to the SDK helper
/// (`cokret_core::models::handle::normalize_handle_localpart`) so any
/// script-mixed or homograph-confusable handle is rejected with the
/// `handle_homograph_forbidden` reason code before the ASCII allow-list
/// kicks in. See `_before_todos.md §0.14` for the normative wording.
pub fn is_valid_handle(handle: &str) -> bool {
    classify_handle(handle).is_ok()
}

/// HDL-1 — full handle validity classification.
///
/// Returns `Ok(())` for a valid handle. On rejection, returns a tuple
/// `(reason_code, message)` so the caller can surface the canonical
/// reason code (`handle_homograph_forbidden` for script-mixed or
/// confusable handles per UTS#39, otherwise the generic
/// `handle_invalid_format`).
///
/// TODO(R4): when the SDK exposes a richer error breakdown distinguishing
/// "script-mixed" from "confusable skeleton collision", surface both
/// reason codes separately; today both fold into
/// `handle_homograph_forbidden`.
pub fn classify_handle(handle: &str) -> Result<(), (&'static str, &'static str)> {
    let normalized = normalize_handle(handle);
    if normalized.len() <= 1 {
        return Err(("handle_invalid_format", "handle MUST be non-empty"));
    }
    let localpart = normalized.trim_start_matches('@');
    // Wire-level homograph guard (HDL-1). SDK helper enforces NFC +
    // UTS#39 confusable skeleton + script-mix reject. Any failure here
    // is surfaced as `handle_homograph_forbidden` so call sites can
    // distinguish from the plain ASCII allow-list reject below.
    if cokret_sdk::models::normalize_handle_localpart(localpart).is_err() {
        return Err((
            "handle_homograph_forbidden",
            "handle localpart fails NFC + UTS#39 confusable skeleton + script-mixed reject",
        ));
    }
    if !localpart
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err((
            "handle_invalid_format",
            "handle localpart must be lowercase ASCII alphanumeric + `-_.`",
        ));
    }
    Ok(())
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

/// Bare localpart form stored on `AccountRecord` / `accounts.localpart`:
/// trimmed, lowercase, no leading `@`. The domain half of the canonical
/// `<localpart>:<domain>` handle is never stored — it is implicitly this
/// server's own service domain, so a domain rename never rewrites rows.
pub fn normalize_localpart(handle: &str) -> String {
    normalize_handle(handle).trim_start_matches('@').to_owned()
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
// (The `entity` abstraction never landed in `cokret-spec/v1`; typed
// objects in the protocol are `ck:space:` / `ck:strand:` / `ck:morph:` /
// `ck:relation:` / `ck:view:`, each driven by its own dedicated event
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

#[cfg(test)]
mod tests {
    use super::*;

    /// CKP-0008 / CKP-0009 (B-D, P2-G) — soland's inbound DID validator
    /// MUST route through the SDK `Did::new` parser. Regression guard so
    /// the wire ingress points (event_log envelope, agents.rs handlers,
    /// account.register, etc.) stay aligned with the spec DID format.
    #[test]
    fn validate_did_routes_through_sdk_parser() {
        assert!(validate_did("did:web:alice.example").is_ok());
        assert!(validate_did("did:key:z6Mki7v1mC9ATsB4VxAfqgZTLZbDpKpUjk78aWxNqQuqQqQu").is_ok());
        // Empty / scheme-less / wrong scheme MUST fail. The SDK validator
        // is the source of truth — we just assert the wrapper bubbles the
        // error.
        assert!(validate_did("").is_err());
        assert!(validate_did("not-a-did").is_err());
        assert!(validate_did("http://example.com").is_err());
        assert!(validate_did("did:").is_err());
    }
}
