//! `did:webvh` log validation primitives (G3.S3 — subset scope).
//!
//! Implements the deterministic, well-bounded validations the resolver
//! used to skip:
//!
//! 1. **prev_hash chain validation** — every non-genesis entry MUST link to
//!    the prior entry by carrying that entry's `versionId` in its own
//!    `previousVersionId` field, AND the hash portion of the entry's own
//!    `versionId` MUST match the canonical hash of the (proof- /
//!    versionId-stripped) entry. Spec: `identity/identity-did.md` §3.4
//!    ("entry hash chain") and the DIF didwebvh v1.0 method spec.
//! 2. **SCID mismatch rejection** — the SCID embedded in the DID string
//!    MUST equal the SCID derivable from the genesis entry (§3 / §3.4 —
//!    "DNS hijack protection" / "可审计的 DID 控制历史").
//! 3. **Witness signature verification** — when a single witness proof is
//!    present on an entry it MUST verify against an `updateKeys`-listed
//!    public key. Multi-witness quorum, the 24h `degraded_no_witness`
//!    window, and emergency rotation are explicitly out of scope here and
//!    carry `TODO(G3.S3-followup)` markers (see callers).
//!
//! Canonical JSON uses `contrix_sdk::canonical::canonical_json_bytes`
//! (`encoding.md` §2 — deterministic, integer-only number profile) — the
//! same helper the embedded provider uses to derive the SCID and entry
//! hashes, so validation and production stay in lockstep.

use ed25519_dalek::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, Signature, Verifier, VerifyingKey};
use salvo::http::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::error::{AppError, ErrorCode};

const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];
const WEBVH_SCID_PLACEHOLDER: &str = "{SCID}";

/// A `did:webvh` log entry as it appears on the wire. We keep the
/// underlying `serde_json::Value` so the validator stays agnostic of the
/// DIF didwebvh struct evolution — the chain / SCID / signature rules
/// only need a stable canonical encoding, not a typed projection.
#[derive(Clone, Debug)]
pub struct WebvhLogEntry {
    pub payload: Value,
}

impl WebvhLogEntry {
    pub fn new(payload: Value) -> Self {
        Self { payload }
    }

    /// `versionId` is `"<seq>-<multibase-multihash>"`. Splits on the first
    /// `-` so the hash portion is callable in its own right.
    pub fn version_id(&self) -> Option<&str> {
        self.payload.get("versionId").and_then(Value::as_str)
    }

    pub fn previous_version_id(&self) -> Option<&str> {
        self.payload
            .get("previousVersionId")
            .and_then(Value::as_str)
    }
}

/// Stable error envelope for webvh validation failures. Maps to the
/// canonical soland `AppError` via `From`, so call-sites can `?` it like
/// any other typed handler error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebvhValidationError {
    /// Entry at `at_index` declares `previousVersionId = actual` but the
    /// prior entry's `versionId` is `expected`, OR the entry's own
    /// versionId hash does not match the canonical hash of its content.
    ChainBreak {
        at_index: usize,
        expected: String,
        actual: String,
    },
    /// The SCID encoded in the DID does not equal the SCID derived from
    /// the genesis log entry's parameters.
    ScidMismatch { in_did: String, derived: String },
    /// A witness proof was present but failed signature verification
    /// (bad key, bad signature bytes, or signer not on `updateKeys`).
    WitnessSignatureInvalid { reason: String },
    /// The log was empty — every did:webvh resolve MUST have at least the
    /// genesis entry, so this is treated as a hard chain break too.
    EmptyLog,
    /// The log entry's wire shape was unusable (missing `versionId`,
    /// non-canonical encoding, etc). Treated as a chain break because
    /// the offending entry cannot be hashed.
    MalformedEntry { at_index: usize, reason: String },
}

impl WebvhValidationError {
    /// Stable string code (registry naming convention) — these are the
    /// strings clients/tests assert against. They line up with the
    /// `webvh_*` family in `identity-did.md` §3.4 / §4.2.1.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ChainBreak { .. } => "webvh_chain_break",
            Self::ScidMismatch { .. } => "webvh_scid_mismatch",
            Self::WitnessSignatureInvalid { .. } => "webvh_witness_signature_invalid",
            Self::EmptyLog => "webvh_empty_log",
            Self::MalformedEntry { .. } => "webvh_malformed_entry",
        }
    }

    /// HTTP status: integrity / shape failures are 422 Unprocessable
    /// Entity (`SchemaViolation` in the soland registry), signature
    /// failures are 401 Unauthorized (`InvalidSignature`).
    pub fn http_status(&self) -> StatusCode {
        match self {
            Self::ChainBreak { .. }
            | Self::ScidMismatch { .. }
            | Self::EmptyLog
            | Self::MalformedEntry { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            Self::WitnessSignatureInvalid { .. } => StatusCode::UNAUTHORIZED,
        }
    }

    /// Human-readable message — included verbatim in the error envelope's
    /// `error` field.
    pub fn message(&self) -> String {
        match self {
            Self::ChainBreak {
                at_index,
                expected,
                actual,
            } => format!(
                "did:webvh log chain break at index {at_index}: expected {expected}, got {actual}"
            ),
            Self::ScidMismatch { in_did, derived } => format!(
                "did:webvh SCID mismatch: DID embeds {in_did}, derived from genesis is {derived}"
            ),
            Self::WitnessSignatureInvalid { reason } => {
                format!("did:webvh witness signature invalid: {reason}")
            }
            Self::EmptyLog => "did:webvh log is empty".to_owned(),
            Self::MalformedEntry { at_index, reason } => {
                format!("did:webvh log entry at index {at_index} is malformed: {reason}")
            }
        }
    }
}

impl std::fmt::Display for WebvhValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for WebvhValidationError {}

impl From<WebvhValidationError> for AppError {
    fn from(error: WebvhValidationError) -> Self {
        let status = error.http_status();
        let wire_code = error.code().to_owned();
        // Pick the closest registry-canonical ErrorCode so structured
        // logging / metrics still see a known variant; the wire-code
        // override carries the precise `webvh_*` label.
        let code = match status {
            StatusCode::UNAUTHORIZED => ErrorCode::InvalidSignature,
            _ => ErrorCode::SchemaViolation,
        };
        AppError::new(code, error.message())
            .with_status(status)
            .with_wire_code(wire_code)
    }
}

/// Iterate pairwise over a log and reject the first chain break.
///
/// Spec: `identity/identity-did.md` §3.4 — `did:webvh` provides
/// "`did.jsonl` 历史 (SCID + entry hash chain + controller proof)" —
/// and the embedded provider uses `versionId = "<seq>-<multibase-multihash>"`
/// where the multihash is sha256 over the canonical JSON of the entry
/// with `proof` and `versionId` stripped (see `webvh_entry_hash` below;
/// matches the helper used during write in `did.rs`).
pub fn validate_log_chain(log: &[WebvhLogEntry]) -> Result<(), WebvhValidationError> {
    if log.is_empty() {
        return Err(WebvhValidationError::EmptyLog);
    }
    // Genesis check — versionId hash must equal canonical hash of the
    // stripped entry. (We do not require previousVersionId on entry 0.)
    let genesis_version_id =
        log[0]
            .version_id()
            .ok_or_else(|| WebvhValidationError::MalformedEntry {
                at_index: 0,
                reason: "missing versionId".to_owned(),
            })?;
    let (_genesis_seq, genesis_hash) = split_version_id(genesis_version_id).ok_or_else(|| {
        WebvhValidationError::MalformedEntry {
            at_index: 0,
            reason: "versionId must be \"<seq>-<hash>\"".to_owned(),
        }
    })?;
    let recomputed_genesis = webvh_entry_hash(&log[0].payload).map_err(|reason| {
        WebvhValidationError::MalformedEntry {
            at_index: 0,
            reason,
        }
    })?;
    if recomputed_genesis != genesis_hash {
        return Err(WebvhValidationError::ChainBreak {
            at_index: 0,
            expected: recomputed_genesis,
            actual: genesis_hash.to_owned(),
        });
    }
    for index in 1..log.len() {
        let prev = &log[index - 1];
        let current = &log[index];
        let prev_version_id =
            prev.version_id()
                .ok_or_else(|| WebvhValidationError::MalformedEntry {
                    at_index: index - 1,
                    reason: "missing versionId".to_owned(),
                })?;
        let declared_prev =
            current
                .previous_version_id()
                .ok_or_else(|| WebvhValidationError::MalformedEntry {
                    at_index: index,
                    reason: "non-genesis entry must declare previousVersionId".to_owned(),
                })?;
        if declared_prev != prev_version_id {
            return Err(WebvhValidationError::ChainBreak {
                at_index: index,
                expected: prev_version_id.to_owned(),
                actual: declared_prev.to_owned(),
            });
        }
        // Recompute current entry's hash against the hash portion of
        // its own versionId — this catches in-place tampering with the
        // payload even when previousVersionId still happens to match.
        let current_version_id =
            current
                .version_id()
                .ok_or_else(|| WebvhValidationError::MalformedEntry {
                    at_index: index,
                    reason: "missing versionId".to_owned(),
                })?;
        let (_seq, current_hash) = split_version_id(current_version_id).ok_or_else(|| {
            WebvhValidationError::MalformedEntry {
                at_index: index,
                reason: "versionId must be \"<seq>-<hash>\"".to_owned(),
            }
        })?;
        let recomputed = webvh_entry_hash(&current.payload).map_err(|reason| {
            WebvhValidationError::MalformedEntry {
                at_index: index,
                reason,
            }
        })?;
        if recomputed != current_hash {
            return Err(WebvhValidationError::ChainBreak {
                at_index: index,
                expected: recomputed,
                actual: current_hash.to_owned(),
            });
        }
    }
    Ok(())
}

/// Derive the SCID a DID claims, from its genesis log entry.
///
/// The DIF didwebvh v1.0 spec defines the SCID as the multibase multihash
/// of the canonical JSON of the genesis entry with all `{SCID}`
/// occurrences (the embedded provider's placeholder convention) and the
/// `proof` / `versionId` fields stripped. We rebuild that skeleton from
/// the genesis entry — which is what the embedded provider also does at
/// write time (see `derive_webvh_scid` in `did.rs`).
pub fn derive_scid_from_genesis(genesis: &WebvhLogEntry) -> Result<String, WebvhValidationError> {
    let skeleton = scid_skeleton_from_genesis(&genesis.payload).map_err(|reason| {
        WebvhValidationError::MalformedEntry {
            at_index: 0,
            reason,
        }
    })?;
    let canonical = contrix_sdk::canonical::canonical_json_bytes(&skeleton).map_err(|error| {
        WebvhValidationError::MalformedEntry {
            at_index: 0,
            reason: error.to_string(),
        }
    })?;
    Ok(sha256_multihash_multibase(&canonical))
}

/// Parse the SCID embedded in a `did:webvh:<scid>:<host-and-path>` DID.
/// Returns `None` when the string is not a well-formed did:webvh.
pub fn scid_from_did(did: &str) -> Option<&str> {
    let rest = did.strip_prefix("did:webvh:")?;
    let scid_end = rest.find(':')?;
    Some(&rest[..scid_end])
}

/// Verify that a DID's claimed SCID matches the SCID derivable from its
/// genesis log entry. Convenience wrapper that composes `scid_from_did`
/// + `derive_scid_from_genesis`.
pub fn verify_scid_against_did(
    did: &str,
    genesis: &WebvhLogEntry,
) -> Result<(), WebvhValidationError> {
    let claimed = scid_from_did(did).ok_or_else(|| WebvhValidationError::ScidMismatch {
        in_did: did.to_owned(),
        derived: "<no scid in did>".to_owned(),
    })?;
    let derived = derive_scid_from_genesis(genesis)?;
    if claimed != derived {
        return Err(WebvhValidationError::ScidMismatch {
            in_did: claimed.to_owned(),
            derived,
        });
    }
    Ok(())
}

/// Verify a single witness signature on a log entry, when one is
/// present. The proof structure mirrors the controller proof
/// (`DataIntegrityProof` / `eddsa-jcs-2022`) the embedded provider
/// already verifies — the only difference is that the verification
/// method must point at one of the configured / declared witness keys
/// rather than `updateKeys`.
///
/// `accepted_witness_keys` is the multibase-encoded public key set the
/// caller considers authoritative (resolver policy `trusted_witnesses`
/// keys, or the keys declared inside the genesis entry's
/// `parameters.witnesses`). An empty list means "no witness expected" —
/// we return `Ok(())` in that case (which the caller maps to
/// `degraded_no_witness` higher up).
///
/// TODO(G3.S3-followup): multi-witness quorum + 24h degraded window.
/// This helper only validates **one** witness signature shape. The full
/// `{witness_quorum, partial_signatures, fold}` pipeline + the
/// `degraded_no_witness` 24h state machine (`identity-did.md` §4.2.1)
/// belong to the next slice.
pub fn verify_witness_signature(
    entry: &WebvhLogEntry,
    accepted_witness_keys: &[String],
) -> Result<(), WebvhValidationError> {
    let Some(proofs) = entry.payload.get("witness").and_then(Value::as_array) else {
        // No witness proof attached — degraded mode handling is the
        // caller's problem (see TODO above). Return Ok so we don't
        // double-fail when a deployment legitimately runs without
        // witnesses.
        return Ok(());
    };
    let Some(proof) = proofs.first().and_then(Value::as_object) else {
        return Ok(());
    };
    let proof_type = proof
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if proof_type != "DataIntegrityProof" {
        return Err(WebvhValidationError::WitnessSignatureInvalid {
            reason: format!("proof type must be DataIntegrityProof, got {proof_type:?}"),
        });
    }
    let cryptosuite = proof
        .get("cryptosuite")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if cryptosuite != "eddsa-jcs-2022" {
        return Err(WebvhValidationError::WitnessSignatureInvalid {
            reason: format!("proof cryptosuite must be eddsa-jcs-2022, got {cryptosuite:?}"),
        });
    }
    let verification_method = proof
        .get("verificationMethod")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let public_key_multibase = verification_method
        .rsplit_once('#')
        .map(|(_, fragment)| fragment)
        .unwrap_or(verification_method);
    if !accepted_witness_keys.is_empty()
        && !accepted_witness_keys
            .iter()
            .any(|key| key == public_key_multibase)
    {
        return Err(WebvhValidationError::WitnessSignatureInvalid {
            reason: "verificationMethod does not match any accepted witness key".to_owned(),
        });
    }
    let public_key = decode_ed25519_public_key(public_key_multibase)
        .map_err(|reason| WebvhValidationError::WitnessSignatureInvalid { reason })?;
    let signature = decode_webvh_signature(
        proof
            .get("proofValue")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )
    .map_err(|reason| WebvhValidationError::WitnessSignatureInvalid { reason })?;
    let mut canonical_entry = entry.payload.clone();
    if let Value::Object(map) = &mut canonical_entry {
        map.remove("witness");
        map.remove("proof");
    }
    let payload =
        contrix_sdk::canonical::canonical_json_bytes(&canonical_entry).map_err(|error| {
            WebvhValidationError::WitnessSignatureInvalid {
                reason: error.to_string(),
            }
        })?;
    public_key.verify(&payload, &signature).map_err(|_| {
        WebvhValidationError::WitnessSignatureInvalid {
            reason: "ed25519 verification failed".to_owned(),
        }
    })
}

// ── internals ───────────────────────────────────────────────────────────

fn split_version_id(version_id: &str) -> Option<(u64, &str)> {
    let (seq, hash) = version_id.split_once('-')?;
    let seq: u64 = seq.parse().ok()?;
    if hash.is_empty() {
        return None;
    }
    Some((seq, hash))
}

fn webvh_entry_hash(entry: &Value) -> Result<String, String> {
    let mut stripped = entry.clone();
    if let Value::Object(map) = &mut stripped {
        map.remove("proof");
        map.remove("versionId");
        // `witness` is part of the entry contents for chain-hash
        // purposes (so witness signatures bind to the same bytes as
        // controller signatures), but we still strip it here because
        // the embedded provider's `strip_webvh_entry_for_hash` in
        // `did.rs` does the same — keeping the two paths aligned.
    }
    let canonical = contrix_sdk::canonical::canonical_json_bytes(&stripped)
        .map_err(|error| error.to_string())?;
    Ok(sha256_multihash_multibase(&canonical))
}

/// Recreate the canonical SCID-derivation skeleton from a genesis entry:
/// every occurrence of the realised SCID is swapped back to the
/// `{SCID}` placeholder, and `proof` / `versionId` are removed. The
/// embedded provider builds the same skeleton at write time
/// (`derive_webvh_scid` in `did.rs`).
fn scid_skeleton_from_genesis(entry: &Value) -> Result<Value, String> {
    let claimed_scid = entry
        .pointer("/parameters/scid")
        .and_then(Value::as_str)
        .ok_or_else(|| "genesis entry must declare parameters.scid".to_owned())?
        .to_owned();
    let mut stripped = entry.clone();
    if let Value::Object(map) = &mut stripped {
        map.remove("proof");
        map.remove("versionId");
        map.remove("witness");
    }
    let text = serde_json::to_string(&stripped).map_err(|e| e.to_string())?;
    let substituted = text.replace(&claimed_scid, WEBVH_SCID_PLACEHOLDER);
    // Restore the placeholder versionId shape so the skeleton matches
    // what the embedded provider hashed when deriving the SCID at write
    // time — `{seq}-{SCID}` for the inception entry.
    let mut skeleton: Value = serde_json::from_str(&substituted).map_err(|e| e.to_string())?;
    if let Value::Object(map) = &mut skeleton {
        map.insert(
            "versionId".to_owned(),
            json!(format!("0-{WEBVH_SCID_PLACEHOLDER}")),
        );
    }
    Ok(skeleton)
}

fn sha256_multihash_multibase(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut multihash = Vec::with_capacity(34);
    multihash.push(0x12); // sha2-256
    multihash.push(0x20); // 32 bytes
    multihash.extend_from_slice(&digest);
    format!("z{}", bs58::encode(multihash).into_string())
}

fn decode_ed25519_public_key(value: &str) -> Result<VerifyingKey, String> {
    let rest = value
        .strip_prefix('z')
        .ok_or_else(|| "public key must use base58btc multibase".to_owned())?;
    let raw = bs58::decode(rest)
        .into_vec()
        .map_err(|error| format!("public key base58 decode failed: {error}"))?;
    let bytes = raw
        .strip_prefix(&ED25519_MULTICODEC_PREFIX)
        .ok_or_else(|| "public key must be ed25519-pub multicodec".to_owned())?;
    if bytes.len() != PUBLIC_KEY_LENGTH {
        return Err("ed25519 public key must be 32 bytes".to_owned());
    }
    let mut key_bytes = [0u8; PUBLIC_KEY_LENGTH];
    key_bytes.copy_from_slice(bytes);
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| "invalid ed25519 public key".to_owned())
}

fn decode_webvh_signature(value: &str) -> Result<Signature, String> {
    let rest = value
        .strip_prefix('z')
        .ok_or_else(|| "proofValue must use base58btc multibase".to_owned())?;
    let raw = bs58::decode(rest)
        .into_vec()
        .map_err(|error| format!("proofValue base58 decode failed: {error}"))?;
    if raw.len() != SIGNATURE_LENGTH {
        return Err("ed25519 proofValue must be 64 bytes".to_owned());
    }
    let mut signature_bytes = [0u8; SIGNATURE_LENGTH];
    signature_bytes.copy_from_slice(&raw);
    Ok(Signature::from_bytes(&signature_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::RngCore;

    fn fresh_signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    fn encode_pubkey_multibase(key: &VerifyingKey) -> String {
        let mut buf = Vec::with_capacity(2 + PUBLIC_KEY_LENGTH);
        buf.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
        buf.extend_from_slice(&key.to_bytes());
        format!("z{}", bs58::encode(buf).into_string())
    }

    fn encode_sig_multibase(sig: &Signature) -> String {
        format!("z{}", bs58::encode(sig.to_bytes()).into_string())
    }

    /// Build a genesis log entry with a self-consistent SCID + versionId.
    fn build_genesis(update_key_multibase: &str) -> (String, WebvhLogEntry) {
        // 1) Build the SCID-derivation skeleton (placeholder SCID).
        let skeleton = json!({
            "versionId": format!("0-{WEBVH_SCID_PLACEHOLDER}"),
            "versionTime": "2026-05-21T00:00:00Z",
            "parameters": {
                "scid": WEBVH_SCID_PLACEHOLDER,
                "method": "did:webvh:1.0",
                "updateKeys": [update_key_multibase],
            },
            "state": {
                "id": format!("did:webvh:{WEBVH_SCID_PLACEHOLDER}:test.example:webvh:alice"),
            },
        });
        let canonical = contrix_sdk::canonical::canonical_json_bytes(&skeleton).unwrap();
        let scid = sha256_multihash_multibase(&canonical);
        // 2) Substitute the real SCID back in everywhere.
        let text = serde_json::to_string(&skeleton).unwrap();
        let realised: Value =
            serde_json::from_str(&text.replace(WEBVH_SCID_PLACEHOLDER, &scid)).unwrap();
        // 3) Compute the entry's own versionId hash.
        let entry_hash = webvh_entry_hash(&realised).unwrap();
        let mut entry = realised;
        if let Value::Object(map) = &mut entry {
            map.insert("versionId".to_owned(), json!(format!("1-{entry_hash}")));
        }
        (scid, WebvhLogEntry::new(entry))
    }

    /// Build entry 2 linked to a genesis entry (correct chain).
    fn build_entry_two(prev: &WebvhLogEntry, scid: &str) -> WebvhLogEntry {
        let body = json!({
            "versionTime": "2026-05-22T00:00:00Z",
            "previousVersionId": prev.version_id().unwrap(),
            "parameters": {
                "scid": scid,
                "method": "did:webvh:1.0",
                "updateKeys": ["z6MkrotatedKey00000000000000000000000000000"],
            },
            "state": {
                "id": format!("did:webvh:{scid}:test.example:webvh:alice"),
            },
        });
        let hash = webvh_entry_hash(&body).unwrap();
        let mut entry = body;
        if let Value::Object(map) = &mut entry {
            map.insert("versionId".to_owned(), json!(format!("2-{hash}")));
        }
        WebvhLogEntry::new(entry)
    }

    #[test]
    fn chain_ok_accepts_well_formed_two_entry_log() {
        let signing = fresh_signing_key();
        let pubkey_mb = encode_pubkey_multibase(&signing.verifying_key());
        let (scid, genesis) = build_genesis(&pubkey_mb);
        let entry_two = build_entry_two(&genesis, &scid);
        let log = vec![genesis, entry_two];
        validate_log_chain(&log).expect("chain should validate");
    }

    #[test]
    fn chain_break_detects_tampered_previous_version_id() {
        let signing = fresh_signing_key();
        let pubkey_mb = encode_pubkey_multibase(&signing.verifying_key());
        let (scid, genesis) = build_genesis(&pubkey_mb);
        let mut entry_two = build_entry_two(&genesis, &scid).payload;
        if let Value::Object(map) = &mut entry_two {
            map.insert(
                "previousVersionId".to_owned(),
                json!("1-zForgedPreviousHash000000000000000000000000"),
            );
            // Recompute this entry's own versionId so we isolate the
            // failure to the previousVersionId mismatch (otherwise the
            // self-hash check fires first).
            let recomputed = webvh_entry_hash(&Value::Object(map.clone())).unwrap();
            map.insert("versionId".to_owned(), json!(format!("2-{recomputed}")));
        }
        let log = vec![genesis, WebvhLogEntry::new(entry_two)];
        let err = validate_log_chain(&log).expect_err("chain should break");
        match err {
            WebvhValidationError::ChainBreak { at_index, .. } => assert_eq!(at_index, 1),
            other => panic!("expected ChainBreak, got {other:?}"),
        }
    }

    #[test]
    fn scid_mismatch_detects_forged_did() {
        let signing = fresh_signing_key();
        let pubkey_mb = encode_pubkey_multibase(&signing.verifying_key());
        let (_scid, genesis) = build_genesis(&pubkey_mb);
        let forged_did =
            "did:webvh:zForgedScid000000000000000000000000000000000:test.example:webvh:alice";
        let err = verify_scid_against_did(forged_did, &genesis).expect_err("scid should mismatch");
        match err {
            WebvhValidationError::ScidMismatch { .. } => {}
            other => panic!("expected ScidMismatch, got {other:?}"),
        }
    }

    #[test]
    fn scid_match_accepts_genuine_did() {
        let signing = fresh_signing_key();
        let pubkey_mb = encode_pubkey_multibase(&signing.verifying_key());
        let (scid, genesis) = build_genesis(&pubkey_mb);
        let real_did = format!("did:webvh:{scid}:test.example:webvh:alice");
        verify_scid_against_did(&real_did, &genesis).expect("scid should match");
    }

    #[test]
    fn witness_sig_invalid_rejects_forged_signature() {
        let witness = fresh_signing_key();
        let witness_pubkey_mb = encode_pubkey_multibase(&witness.verifying_key());
        // An entirely separate key produced the (forged) signature.
        let forger = fresh_signing_key();
        let entry_body = json!({
            "versionId": "1-zSomeHash",
            "versionTime": "2026-05-21T00:00:00Z",
            "parameters": {"method": "did:webvh:1.0"},
        });
        // Sign canonical bytes of entry_body (without `witness`) with
        // the forger key; attach as if it were the witness's signature.
        let canonical = contrix_sdk::canonical::canonical_json_bytes(&entry_body).unwrap();
        let forged_sig = forger.sign(&canonical);
        let mut payload = entry_body;
        if let Value::Object(map) = &mut payload {
            map.insert(
                "witness".to_owned(),
                json!([{
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "verificationMethod": format!("did:web:witness.example#{witness_pubkey_mb}"),
                    "proofValue": encode_sig_multibase(&forged_sig),
                }]),
            );
        }
        let entry = WebvhLogEntry::new(payload);
        let err = verify_witness_signature(&entry, &[witness_pubkey_mb])
            .expect_err("forged witness signature must fail");
        match err {
            WebvhValidationError::WitnessSignatureInvalid { .. } => {}
            other => panic!("expected WitnessSignatureInvalid, got {other:?}"),
        }
        // And the typed error envelope must surface 401 + the right code.
        let app: AppError = err.into();
        assert_eq!(app.http_status(), StatusCode::UNAUTHORIZED);
        assert_eq!(app.wire_code(), "webvh_witness_signature_invalid");
    }
}
