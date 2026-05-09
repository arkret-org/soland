//! Production JWS (RFC 7515) Ed25519 detached-signature verifier.
//!
//! T7-9 (2026-05-09 十一轮): real cryptographic verification of Move /
//! Anchor signatures via the AppState DID resolver chain (
//! `did:key` / `did:web` / `did:webvh` / static).
//!
//! # Two-tier verifier model
//!
//! - Dev mode (`config.development_mode == true`): handlers use
//!   `routing::move_anchor::verify_jws_shape` — RFC 7515 §3.2 detached
//!   shape, alg = EdDSA, no zero-sentinel signature, no actual crypto.
//!   Lets test fixtures and local dev iterate without managing real keys.
//! - Production mode (default): handlers use [`verify_jws_ed25519`] via
//!   [`AppState::jws_verifier`]'s closure factory — same shape checks
//!   PLUS DID resolution + Ed25519 public-key extraction + RFC 7515 §5.2
//!   signing-input reconstruction + ed25519-dalek verify.
//!
//! # Detached JWS shape (recap)
//!
//! ```text
//! BASE64URL(JOSE_HEADER) || '.' || /* empty payload */ || '.' || BASE64URL(SIGNATURE)
//! ```
//!
//! The signer's input was
//! `BASE64URL(JOSE_HEADER) || '.' || BASE64URL(canonical_bytes)`. To
//! verify, reconstruct that string and run `verify(signing_input, sig)`
//! against the resolved public key.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use contrix_sdk::Did;
use contrix_sdk::Hlc;
use contrix_sdk::identity::DidResolver;

use crate::state::AppState;

/// Production Ed25519 detached-JWS verifier.
///
/// Returns `Ok(())` on successful verification (shape valid + DID resolves
/// + signature checks against `canonical_bytes`); `Err(message)` otherwise.
/// All error paths are uniform — any deviation from spec rejects with a
/// descriptive reason (callers map to `schema_violation` 4xx, never 5xx).
pub fn verify_jws_ed25519(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    issuer: &str,
    state: &AppState,
) -> Result<(), String> {
    // Step 1: shape validation. Identical to `verify_jws_shape` so dev
    // / prod paths reject the same malformed inputs the same way.
    let (protected_b64, signature_b64) = parse_detached_jws(jws)?;
    if verification_method.is_empty() {
        return Err("empty verification_method".to_owned());
    }
    if issuer.is_empty() {
        return Err("empty issuer".to_owned());
    }
    if canonical_bytes.is_empty() {
        return Err("empty canonical bytes".to_owned());
    }

    // Step 2: protected header must declare alg=EdDSA.
    let header_bytes = URL_SAFE_NO_PAD
        .decode(protected_b64)
        .map_err(|e| format!("JWS header is not base64url: {e}"))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("JWS header is not JSON: {e}"))?;
    let alg = header.get("alg").and_then(serde_json::Value::as_str).unwrap_or("");
    if alg != "EdDSA" {
        return Err(format!("JWS alg `{alg}` is not EdDSA"));
    }

    // Step 3: signature segment must decode to a 64-byte Ed25519 signature.
    if signature_b64.bytes().all(|b| b == b'A') {
        return Err("JWS signature is the all-zero sentinel".to_owned());
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|e| format!("JWS signature is not base64url: {e}"))?;
    if signature_bytes.len() != 64 {
        return Err(format!(
            "Ed25519 signature must be 64 bytes, got {}",
            signature_bytes.len()
        ));
    }
    let signature_array: [u8; 64] = signature_bytes.try_into().expect("len checked above");
    let signature = Signature::from_bytes(&signature_array);

    // Step 4: resolve verification_method via the DID resolver chain.
    let public_key = resolve_ed25519_pubkey(state, verification_method)?;

    // Step 5: reconstruct the signing input per RFC 7515 §5.2 with the
    // (now known) canonical_bytes payload.
    let payload_b64 = URL_SAFE_NO_PAD.encode(canonical_bytes);
    let signing_input = format!("{protected_b64}.{payload_b64}");

    // Step 6: verify.
    public_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|e| format!("Ed25519 verify failed: {e}"))
}

/// Resolve a DID URL (`<did>#<key_id>` or just a fragment-less DID) to
/// its Ed25519 [`VerifyingKey`] via [`AppState::did_resolver`].
///
/// Accepts:
///   - Full DID URL: `did:web:alice.example#k1` — resolves the DID, then
///     looks up `verification_methods["did:web:alice.example#k1"]`.
///   - Fragment fallback: if the full URL isn't a key, also tries the
///     fragment-only key id (`#k1` → `k1`).
///   - did:key: the multibase-encoded key is in the DID itself; resolve
///     returns a doc whose verification_methods entry points at the same
///     multibase string.
fn resolve_ed25519_pubkey(state: &AppState, verification_method: &str) -> Result<VerifyingKey, String> {
    let (did_str, fragment) = verification_method
        .split_once('#')
        .map(|(d, f)| (d.to_owned(), Some(f.to_owned())))
        .unwrap_or_else(|| (verification_method.to_owned(), None));
    let did = Did::new(did_str.clone()).map_err(|e| format!("invalid DID `{did_str}`: {e}"))?;

    // Resolve via AppState's CompositeDidResolver chain.
    let document = {
        let resolver = state
            .did_resolver
            .lock()
            .map_err(|e| format!("DID resolver lock poisoned: {e}"))?;
        resolver
            .resolve_did(&did)
            .map_err(|e| format!("DID resolve failed for `{did_str}`: {e}"))?
    };

    // Try full URL first, then fragment-only id, then any single-key
    // shortcut (`did:key:` documents typically have one key whose id
    // matches the full URL).
    let multibase = document
        .verification_methods
        .get(verification_method)
        .or_else(|| {
            fragment.as_ref().and_then(|f| document.verification_methods.get(f))
        })
        .or_else(|| {
            // Single-key fallback: if there's exactly one verification
            // method, use it (common for did:key documents).
            if document.verification_methods.len() == 1 {
                document.verification_methods.values().next()
            } else {
                None
            }
        })
        .ok_or_else(|| {
            format!(
                "verification_method `{verification_method}` not found in DID document for `{did_str}` (have {:?})",
                document.verification_methods.keys().collect::<Vec<_>>()
            )
        })?;

    decode_ed25519_multibase(multibase)
}

/// Decode a base58btc-encoded multibase Ed25519 public key.
///
/// Format per W3C did:key + did-core verificationMethod: `z` prefix
/// (base58btc multibase indicator) + base58btc(0xed 0x01 || pubkey32).
/// Strips the multicodec varint (0xed01 = ed25519-pub) and extracts the
/// 32-byte raw key.
fn decode_ed25519_multibase(multibase: &str) -> Result<VerifyingKey, String> {
    let stripped = multibase
        .strip_prefix('z')
        .ok_or_else(|| format!("public key multibase missing `z` prefix: `{multibase}`"))?;
    let decoded = bs58::decode(stripped)
        .into_vec()
        .map_err(|e| format!("base58btc decode failed: {e}"))?;
    if decoded.len() < 2 {
        return Err(format!("multicodec key too short ({} bytes)", decoded.len()));
    }
    // Ed25519-pub multicodec: 0xed 0x01 (varint).
    if decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(format!(
            "expected ed25519-pub multicodec (0xed 0x01), got 0x{:02x} 0x{:02x}",
            decoded[0], decoded[1]
        ));
    }
    let key_bytes = &decoded[2..];
    if key_bytes.len() != 32 {
        return Err(format!(
            "Ed25519 public key must be 32 bytes, got {}",
            key_bytes.len()
        ));
    }
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "Ed25519 public key array conversion failed".to_owned())?;
    VerifyingKey::from_bytes(&key_array)
        .map_err(|e| format!("Ed25519 public key parse failed: {e}"))
}

/// JWS replay protection: verify the SIGNED `Hlc` is within `±window`
/// of wall-clock now. Replay attackers who capture a valid `(canonical_bytes,
/// jws)` pair cannot reuse it past this window because:
///   - The Move's / Anchor's `hlc` is part of `canonical_bytes_for_id` —
///     i.e. it IS in the signed payload (`MoveSignature.created_at` is
///     a separate envelope field that's NOT signed; we deliberately
///     don't trust it).
///   - Same canonical bytes → same content-addressed id → MoveStore /
///     AnchorStore put-pending dedup naturally rejects exact replays of
///     already-stored Moves; the window check protects against replays
///     that haven't reached this server's storage yet (post-restart,
///     federation, etc.).
///
/// `window_seconds = 0` disables the check (returns Ok without inspecting
/// the HLC). Production deploys MUST keep `window_seconds > 0`.
pub fn verify_replay_window(hlc: &Hlc, window_seconds: u64) -> Result<(), String> {
    verify_replay_window_at(hlc, window_seconds, Utc::now())
}

/// C10.B (2026-05-09 十四轮): differentiated replay window for a Move
/// based on the cell families its `effects[]` touch. Looks up each
/// effect's `cell_family` segment in `per_family_overrides`; takes the
/// **minimum** (tightest) override across all touched cells; falls back
/// to `default_window` if no overrides apply. Returns the same shape
/// as [`verify_replay_window`].
///
/// Rationale: Spec event-auth-state-resolution.md §replay calls out that
/// some authority cells (anchorer, mls.epoch) have much tighter freshness
/// requirements than ordinary message events. Picking the min ensures
/// a Move with effects on BOTH anchorer (60s) and an ordinary cell
/// (300s) honors the tighter 60s window.
pub fn verify_replay_window_for_move(
    move_obj: &contrix_sdk::Move,
    default_window_seconds: u64,
    per_family_overrides: &std::collections::BTreeMap<&'static str, u64>,
) -> Result<(), String> {
    verify_replay_window_for_move_at(
        move_obj,
        default_window_seconds,
        per_family_overrides,
        Utc::now(),
    )
}

pub fn verify_replay_window_for_move_at(
    move_obj: &contrix_sdk::Move,
    default_window_seconds: u64,
    per_family_overrides: &std::collections::BTreeMap<&'static str, u64>,
    now: DateTime<Utc>,
) -> Result<(), String> {
    let effective = effective_window_for_move(move_obj, default_window_seconds, per_family_overrides);
    verify_replay_window_at(&move_obj.hlc, effective, now)
}

/// Compute the effective (most-restrictive) replay window for a Move's
/// effects. `default` applies if no effect cell has an override.
pub fn effective_window_for_move(
    move_obj: &contrix_sdk::Move,
    default_window_seconds: u64,
    per_family_overrides: &std::collections::BTreeMap<&'static str, u64>,
) -> u64 {
    let mut effective = default_window_seconds;
    for effect in &move_obj.effects {
        // CellRef shape: `cx:cell:<family>:<subject>` — extract family.
        let Ok(cell_id) = contrix_sdk::CellId::parse(effect.cell.as_str()) else {
            continue;
        };
        let family = cell_id.component();
        if let Some(&override_secs) = per_family_overrides.get(family) {
            // 0 means "disabled" same as default; only a non-zero override
            // can be tighter than default. Special case: if default is 0
            // (disabled) and override is non-zero, the override wins (it
            // tightens an otherwise-disabled check).
            effective = if effective == 0 {
                override_secs
            } else {
                effective.min(override_secs)
            };
        }
    }
    effective
}

/// Same as [`verify_replay_window`] but with an injectable wall-clock
/// reference for unit tests.
pub fn verify_replay_window_at(
    hlc: &Hlc,
    window_seconds: u64,
    now: DateTime<Utc>,
) -> Result<(), String> {
    if window_seconds == 0 {
        return Ok(());
    }
    let hlc_str = hlc.as_str();
    // HLC format: `<12-hex-physical-ms>-<8-hex-logical>-<8-hex-node>`. The
    // SDK's `Hlc::new` already validated the shape; we just parse the
    // first segment back to milliseconds.
    let physical_hex = hlc_str
        .split('-')
        .next()
        .ok_or_else(|| format!("invalid HLC format `{hlc_str}` (no segments)"))?;
    let physical_ms = i64::from_str_radix(physical_hex, 16)
        .map_err(|e| format!("HLC physical-ms hex `{physical_hex}` parse failed: {e}"))?;
    let signed_at = DateTime::<Utc>::from_timestamp_millis(physical_ms).ok_or_else(|| {
        format!("HLC physical-ms {physical_ms} is out of representable range")
    })?;
    let window = chrono::Duration::seconds(window_seconds as i64);
    let delta = now - signed_at;
    if delta > window {
        return Err(format!(
            "HLC signed at {signed_at} is too old (now-signed = {}s; window = {}s)",
            delta.num_seconds(),
            window_seconds
        ));
    }
    if -delta > window {
        return Err(format!(
            "HLC signed at {signed_at} is too far in the future (signed-now = {}s; window = {}s)",
            (-delta).num_seconds(),
            window_seconds
        ));
    }
    Ok(())
}

/// Parse the detached JWS shape and return `(protected_b64, signature_b64)`.
/// Rejects malformed inputs with the same messages as `verify_jws_shape`.
fn parse_detached_jws(jws: &str) -> Result<(&str, &str), String> {
    if jws.is_empty() {
        return Err("empty JWS string".to_owned());
    }
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(format!(
            "JWS must have 3 dot-separated segments, got {}",
            parts.len()
        ));
    }
    let (header_b64u, payload_b64u, signature_b64u) = (parts[0], parts[1], parts[2]);
    if !payload_b64u.is_empty() {
        return Err("detached JWS payload segment must be empty".to_owned());
    }
    if signature_b64u.is_empty() {
        return Err("JWS signature segment is empty".to_owned());
    }
    Ok((header_b64u, signature_b64u))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Encode an Ed25519 public key as the multibase form used by did:key
    /// and DID Document verificationMethod entries.
    fn encode_ed25519_multibase(verifying_key: &VerifyingKey) -> String {
        let mut bytes = Vec::with_capacity(34);
        bytes.push(0xed);
        bytes.push(0x01);
        bytes.extend_from_slice(verifying_key.as_bytes());
        format!("z{}", bs58::encode(bytes).into_string())
    }

    #[test]
    fn round_trip_multibase_decode_recovers_public_key() {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let verifying = signing.verifying_key();
        let multibase = encode_ed25519_multibase(&verifying);
        let decoded = decode_ed25519_multibase(&multibase).expect("decode");
        assert_eq!(decoded.as_bytes(), verifying.as_bytes());
    }

    #[test]
    fn decode_rejects_wrong_multicodec_prefix() {
        // 0xe7 is secp256k1-pub, not ed25519.
        let mut bytes = vec![0xe7u8, 0x01];
        bytes.extend_from_slice(&[0u8; 32]);
        let mb = format!("z{}", bs58::encode(bytes).into_string());
        let err = decode_ed25519_multibase(&mb).unwrap_err();
        assert!(err.contains("ed25519-pub multicodec"));
    }

    #[test]
    fn decode_rejects_missing_z_prefix() {
        let err = decode_ed25519_multibase("not-multibase").unwrap_err();
        assert!(err.contains("missing `z` prefix"));
    }

    #[test]
    fn parse_detached_jws_accepts_canonical_shape() {
        let (h, s) = parse_detached_jws("aaa..bbb").unwrap();
        assert_eq!(h, "aaa");
        assert_eq!(s, "bbb");
    }

    #[test]
    fn parse_detached_jws_rejects_non_empty_payload() {
        let err = parse_detached_jws("aaa.bbb.ccc").unwrap_err();
        assert!(err.contains("payload segment must be empty"));
    }

    #[test]
    fn parse_detached_jws_rejects_too_few_segments() {
        let err = parse_detached_jws("aaa.bbb").unwrap_err();
        assert!(err.contains("3 dot-separated segments"));
    }

    // ── replay-window tests (十二轮) ──

    fn hlc_at_ms(physical_ms: u64) -> Hlc {
        Hlc::new(format!("{physical_ms:012x}-00000000-aabbccdd")).unwrap()
    }

    #[test]
    fn replay_window_zero_seconds_disables_check_for_any_hlc() {
        // Even an HLC from 1970 passes when window=0.
        let hlc = hlc_at_ms(0);
        verify_replay_window(&hlc, 0).unwrap();
    }

    #[test]
    fn replay_window_accepts_hlc_within_bounds() {
        let now = chrono::Utc::now();
        let hlc = hlc_at_ms(now.timestamp_millis() as u64);
        verify_replay_window_at(&hlc, 300, now).unwrap();
    }

    #[test]
    fn replay_window_rejects_stale_hlc() {
        let now = chrono::Utc::now();
        // 1 hour old, window 5 min.
        let stale_ms = (now - chrono::Duration::hours(1)).timestamp_millis() as u64;
        let hlc = hlc_at_ms(stale_ms);
        let err = verify_replay_window_at(&hlc, 300, now).unwrap_err();
        assert!(
            err.contains("too old"),
            "stale HLC reject reason should mention `too old` (got `{err}`)"
        );
    }

    #[test]
    fn replay_window_rejects_future_hlc() {
        let now = chrono::Utc::now();
        let future_ms = (now + chrono::Duration::hours(1)).timestamp_millis() as u64;
        let hlc = hlc_at_ms(future_ms);
        let err = verify_replay_window_at(&hlc, 300, now).unwrap_err();
        assert!(
            err.contains("future"),
            "future HLC reject reason should mention `future` (got `{err}`)"
        );
    }

    // ── per-family override tests (十四轮) ──

    fn build_test_move_touching(cell_id: &str, hlc_ms: u64) -> contrix_sdk::Move {
        use contrix_sdk::{CellRef, MoveId, MoveSignature, Hash};
        contrix_sdk::Move {
            id: MoveId::new(format!("cx:move:sha256:{}", "1".repeat(64))).unwrap(),
            issuer: contrix_sdk::Did::new("did:web:test").unwrap(),
            space_id: contrix_sdk::SpaceId::new(
                "cx:space:0196419b-0000-7000-8000-000000000000".to_owned(),
            )
            .unwrap(),
            preconditions: vec![],
            effects: vec![contrix_sdk::Effect {
                cell: CellRef::new(cell_id.to_owned()).unwrap(),
                op: contrix_sdk::LatticeOp {
                    op_type: contrix_sdk::LatticeOpType::Set,
                    tag: None,
                    value: Some(serde_json::json!({"shape": "single_did", "did": "did:web:foo"})),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            }],
            anchor_ref: contrix_sdk::AnchorId::new(format!(
                "cx:anchor:sha256:{}",
                "00".repeat(32)
            ))
            .unwrap(),
            refs: vec![],
            hlc: Hlc::new(format!("{hlc_ms:012x}-00000000-aabbccdd")).unwrap(),
            sig: MoveSignature {
                alg: "EdDSA".to_owned(),
                verification_method: "did:web:test#k1".to_owned(),
                payload_hash: Hash::new(format!("sha256:{}", "ff".repeat(32))).unwrap(),
                created_at: chrono::Utc::now(),
                jws: "eyJhbGciOiJFZERTQSJ9..ZmFrZS1zaWctZm9yLXRlc3Rz".to_owned(),
            },
        }
    }

    #[test]
    fn effective_window_picks_default_when_no_overrides_apply() {
        let m = build_test_move_touching(
            "cx:cell:cx.component.message.create.v1:cx.event.foo",
            0,
        );
        let overrides = std::collections::BTreeMap::new();
        assert_eq!(effective_window_for_move(&m, 300, &overrides), 300);
    }

    #[test]
    fn effective_window_uses_anchorer_override_when_anchorer_cell_touched() {
        let m = build_test_move_touching(
            "cx:cell:cx.component.anchorer.v1:cx.space.x",
            0,
        );
        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert("cx.component.anchorer.v1", 60u64);
        // Default 300, anchorer override 60 → effective 60.
        assert_eq!(effective_window_for_move(&m, 300, &overrides), 60);
    }

    #[test]
    fn effective_window_takes_minimum_when_default_tighter_than_override() {
        let m = build_test_move_touching(
            "cx:cell:cx.component.anchorer.v1:cx.space.x",
            0,
        );
        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert("cx.component.anchorer.v1", 600u64); // looser than default
        // Default 300, anchorer override 600 → min = 300 (default wins because tighter).
        assert_eq!(effective_window_for_move(&m, 300, &overrides), 300);
    }

    #[test]
    fn effective_window_zero_default_with_override_uses_override() {
        // Test config has window=0 but spec-critical cells should still
        // be window-checked. The override "wins" in this case.
        let m = build_test_move_touching(
            "cx:cell:cx.component.anchorer.v1:cx.space.x",
            0,
        );
        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert("cx.component.anchorer.v1", 60u64);
        assert_eq!(effective_window_for_move(&m, 0, &overrides), 60);
    }

    #[test]
    fn anchorer_cell_with_60s_override_rejects_2min_old_hlc() {
        let now = chrono::Utc::now();
        let two_min_ago_ms =
            (now - chrono::Duration::minutes(2)).timestamp_millis() as u64;
        let m = build_test_move_touching(
            "cx:cell:cx.component.anchorer.v1:cx.space.x",
            two_min_ago_ms,
        );
        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert("cx.component.anchorer.v1", 60u64);
        let err = verify_replay_window_for_move_at(&m, 300, &overrides, now).unwrap_err();
        assert!(
            err.contains("too old"),
            "anchorer cell with 60s override should reject 2min-old hlc (got `{err}`)"
        );
    }

    #[test]
    fn message_cell_under_default_300s_accepts_2min_old_hlc() {
        let now = chrono::Utc::now();
        let two_min_ago_ms =
            (now - chrono::Duration::minutes(2)).timestamp_millis() as u64;
        let m = build_test_move_touching(
            "cx:cell:cx.component.message.create.v1:cx.event.foo",
            two_min_ago_ms,
        );
        // Default 300s, no override for message family → 2min = 120s < 300s → accept.
        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert("cx.component.anchorer.v1", 60u64);
        verify_replay_window_for_move_at(&m, 300, &overrides, now).unwrap();
    }

    #[test]
    fn replay_window_accepts_hlc_at_exact_boundary() {
        // Build `now` at exact ms granularity so `now - signed_at` matches
        // `window` to the millisecond (HLC physical-ms truncates sub-ms,
        // so the verifier's parsed `signed_at` is also ms-aligned).
        let raw = chrono::Utc::now();
        let now_ms = raw.timestamp_millis();
        let now = DateTime::<Utc>::from_timestamp_millis(now_ms).unwrap();
        // Exactly 300s old — boundary case (delta == window, so still pass).
        let boundary_ms = (now - chrono::Duration::seconds(300)).timestamp_millis() as u64;
        let hlc = hlc_at_ms(boundary_ms);
        verify_replay_window_at(&hlc, 300, now).unwrap();
    }
}
