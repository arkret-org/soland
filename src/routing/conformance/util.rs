//! Forked conformance primitives.
//!
//! These mirror the (currently `pub(crate)`) helpers in
//! `cotest/src/conformance/mod.rs` — canonical JSON, sha256-prefixed digest,
//! opaque cursor encoding. We fork rather than depend on `cotest` directly so
//! soland avoids pulling in the cotest crate's heavy test-only dependency
//! graph (`reqwest`, `jsonschema`, the contrix-http-client, ...).
//!
//! The Contrix spec — not either implementation — is the source of truth, so
//! the two copies must stay byte-for-byte equivalent. Drift is caught by the
//! HTTP conformance suite under `cotest/e2e/tests/conformance/`, which runs
//! the same vectors against the in-process cotest suite and the HTTP surface
//! these handlers expose.

use std::collections::BTreeMap;

use anyhow::Result;
#[cfg(test)]
use anyhow::anyhow;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Canonical-JSON encode a `serde_json::Value`.
///
/// Object keys are sorted lexicographically; arrays preserve their input
/// order; primitives (strings/numbers/booleans/null) are serialized via
/// `serde_json::to_string` so escape rules match the spec encoding profile.
/// No whitespace anywhere.
///
/// Forked from `cotest::conformance::canonical_json`.
pub fn canonical_json(value: &Value) -> Result<String> {
    match value {
        Value::Object(map) => {
            let mut ordered = BTreeMap::new();
            for (key, value) in map {
                ordered.insert(key, canonical_json(value)?);
            }
            let mut out = String::from("{");
            for (index, (key, value)) in ordered.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key)?);
                out.push(':');
                out.push_str(value);
            }
            out.push('}');
            Ok(out)
        }
        Value::Array(items) => {
            let canonical_items = items
                .iter()
                .map(canonical_json)
                .collect::<Result<Vec<_>>>()?;
            Ok(format!("[{}]", canonical_items.join(",")))
        }
        _ => Ok(serde_json::to_string(value)?),
    }
}

/// SHA-256 digest of `bytes`, lowercase hex, prefixed with `sha256:`.
///
/// Forked from `cotest::conformance::sha256_prefixed`.
pub fn sha256_prefixed(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity("sha256:".len() + digest.len() * 2);
    out.push_str("sha256:");
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Opaque cursor shape used by `/conformance/cursor`.
///
/// Forked from `cotest::conformance::CursorShape`. `v` carries the protocol
/// version, `x` is a monotonically-increasing opaque position counter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CursorShape {
    pub v: String,
    pub x: u64,
}

/// Encode a `CursorShape` into the spec-defined opaque token
/// `cx:cursor:<base64url-no-pad(canonical_json)>`.
pub fn encode_cursor_shape(shape: &CursorShape) -> Result<String> {
    let canonical = canonical_json(&serde_json::to_value(shape)?)?;
    Ok(format!(
        "cx:cursor:{}",
        URL_SAFE_NO_PAD.encode(canonical.as_bytes())
    ))
}

/// Inverse of [`encode_cursor_shape`] — primarily for round-trip tests.
#[cfg(test)]
pub fn decode_cursor_shape(encoded: &str) -> Result<CursorShape> {
    let payload = encoded
        .strip_prefix("cx:cursor:")
        .ok_or_else(|| anyhow!("cursor must start with cx:cursor:"))?;
    let bytes = URL_SAFE_NO_PAD.decode(payload)?;
    serde_json::from_slice(&bytes).map_err(Into::into)
}

/// Order a slice of HLC strings lexicographically with `actor_id` tiebreak.
///
/// Each entry is `(hlc, actor)` — the conformance spec breaks ties on
/// equal HLC values by the lexicographically smaller `actor`. The original
/// inputs are preserved (we don't mutate the caller's clocks).
pub fn order_hlc_clocks<T: Clone>(clocks: &[(String, String, T)]) -> Vec<(String, String, T)> {
    let mut sorted = clocks.to_vec();
    sorted.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    sorted
}

/// True when `value` matches the canonical `sha256:<64-lowercase-hex>` shape.
#[cfg(test)]
pub fn looks_like_sha256_digest(value: &str) -> bool {
    value.starts_with("sha256:")
        && value.len() == "sha256:".len() + 64
        && value["sha256:".len()..]
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn canonical_json_sorts_object_keys() {
        let value = json!({ "b": 2, "a": 1 });
        assert_eq!(canonical_json(&value).unwrap(), r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn canonical_json_basic_vector_matches_smoke_test() {
        // The cotest e2e smoke test pins this exact byte-for-byte digest.
        let value = json!({ "b": 2, "a": 1 });
        let canonical = canonical_json(&value).unwrap();
        assert_eq!(canonical, r#"{"a":1,"b":2}"#);
        assert_eq!(
            sha256_prefixed(canonical.as_bytes()),
            "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
        );
    }

    #[test]
    fn canonical_json_nested_objects_recurse() {
        let value = json!({ "z": { "b": 2, "a": 1 }, "a": [3, { "y": 1, "x": 2 }] });
        assert_eq!(
            canonical_json(&value).unwrap(),
            r#"{"a":[3,{"x":2,"y":1}],"z":{"a":1,"b":2}}"#
        );
    }

    #[test]
    fn cursor_round_trip_preserves_shape() {
        let shape = CursorShape {
            v: "1".to_owned(),
            x: 42,
        };
        let encoded = encode_cursor_shape(&shape).unwrap();
        assert!(encoded.starts_with("cx:cursor:"));
        let decoded = decode_cursor_shape(&encoded).unwrap();
        assert_eq!(decoded, shape);
    }

    #[test]
    fn order_hlc_clocks_breaks_ties_by_actor() {
        let clocks = vec![
            ("100".to_owned(), "did:bob".to_owned(), ()),
            ("100".to_owned(), "did:alice".to_owned(), ()),
            ("050".to_owned(), "did:carol".to_owned(), ()),
        ];
        let ordered = order_hlc_clocks(&clocks);
        assert_eq!(ordered[0].1, "did:carol");
        assert_eq!(ordered[1].1, "did:alice");
        assert_eq!(ordered[2].1, "did:bob");
    }

    #[test]
    fn sha256_digest_is_lowercase_prefixed_hex() {
        assert!(looks_like_sha256_digest(&sha256_prefixed(b"hello")));
        assert!(!looks_like_sha256_digest("SHA256:abc"));
        assert!(!looks_like_sha256_digest("sha256:short"));
    }
}
