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

use arkret_core::{Cursor, CursorPurpose, DeviceId, Did, SpaceId};
use salvo::http::header;
use salvo::prelude::*;

pub use crate::error::{render_error, render_error_with_top_level_reason};

/// Pull a single query-string value, decoding `+` to space and any
/// `%XX` percent-escapes back to their raw byte form. Required for
/// typed-id query args like `?space_id=ak:space:...` where browsers
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
/// `ak.self.events.query.scan` / `ak.self.events.stream.subscribe` selectors which accept
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
/// Thin re-export of the SDK [`arkret_core::canonical::sha256_hex`] so soland
/// shares the single canonical hash primitive instead of a local
/// reimplementation.
pub fn sha256_hex(bytes: &[u8]) -> String {
    arkret_core::canonical::sha256_hex(bytes)
}

// ── Token / digest validators ───────────────────────────────────────────────

/// Validate a `ak:cursor:<base64url>` token.
///
/// Delegate the issuing-service wire validation to the SDK cursor model so
/// this transport gate cannot drift from the canonical timestamp field names
/// or purpose-specific TTL rules.
pub fn is_valid_sync_token(token: &str) -> bool {
    Cursor::decode(token).is_ok_and(|cursor| {
        matches!(
            cursor.purpose,
            CursorPurpose::Stream | CursorPurpose::Barrier
        )
    })
}

#[cfg(test)]
mod sync_token_tests {
    use super::*;

    #[test]
    fn accepts_sdk_stream_and_barrier_cursor_wire_shapes() {
        let stream = Cursor::new_at(chrono::Utc::now(), 60_000)
            .expect("stream cursor")
            .with_stateful_handle("a".repeat(22));
        assert!(is_valid_sync_token(
            &stream.encode().expect("encoded stream cursor")
        ));

        let barrier = stream.with_barrier();
        assert!(is_valid_sync_token(
            &barrier.encode().expect("encoded barrier cursor")
        ));
    }
}

/// `sha256:<64 lowercase hex>` shape.
pub fn is_valid_sha256_digest(value: &str) -> bool {
    value.starts_with("sha256:") && arkret_core::Hash::new(value.to_owned()).is_ok()
}

/// Active `<digest-suite>:<64 lowercase hex>` hash shape.
pub fn is_valid_hash_digest(value: &str) -> bool {
    arkret_core::Hash::new(value.to_owned()).is_ok()
}

/// 64 lowercase hex characters.
pub fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
}

// ── Identifier / handle validators ──────────────────────────────────────────

/// Validate and parse a DID.
pub fn validate_did(value: &str) -> arkret_core::Result<Did> {
    Did::new(value.to_owned()).map_err(Into::into)
}

pub fn validate_device_id(value: &str) -> arkret_core::Result<DeviceId> {
    DeviceId::new(value.to_owned()).map_err(Into::into)
}

pub fn validate_space_id(value: &str) -> arkret_core::Result<SpaceId> {
    SpaceId::new(value.to_owned()).map_err(Into::into)
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

/// Bare localpart form: trimmed, lowercase, no leading `@`.
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
// (The `entity` abstraction never landed in `arkret-spec/v1`; typed
// objects in the protocol are `ak:space:` / `ak:strand:` / `ak:morph:` /
// `ak:relation:` / `ak:view:`, each driven by its own dedicated event
// kind.)

/// Allow-list of space-discoverability values.
pub fn is_valid_discoverability(value: &str) -> bool {
    matches!(
        value,
        "public" | "listed" | "restricted" | "unlisted" | "invite_only" | "secret"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AKP-0008 / AKP-0009 (B-D, P2-G) — soland's inbound DID validator
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
