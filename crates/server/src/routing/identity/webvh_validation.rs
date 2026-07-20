//! `did:webvh` log validation primitives (G3.S3 — subset scope).
//!
//! Implements the deterministic, well-bounded validations the resolver
//! used to skip:
//!
//! 1. **versionId hash-chain validation** — the hash portion of every entry's `versionId` MUST
//!    match the canonical hash of the proof-stripped entry after replacing its `versionId` with the
//!    SCID for genesis or the accepted predecessor's `versionId` for later entries. Spec:
//!    `identity/identity-did.md` §3.4 ("entry hash chain") and the DIF didwebvh v1.0 method spec.
//! 2. **SCID mismatch rejection** — the SCID embedded in the DID string MUST equal the SCID
//!    derivable from the genesis entry (§3 / §3.4, covering DNS hijack protection and auditable DID
//!    control history).
//! 3. **Witness signature verification** — every witness proof present on an entry must verify,
//!    distinct valid witnesses are counted toward the configured quorum, and entries with
//!    configured witnesses may only remain in `degraded_no_witness` for 24h. Rotation entries fail
//!    closed immediately when quorum is missing.
//!
//! Canonical JSON uses `arkret_core::canonical::canonical_json_bytes`
//! (`encoding.md` §2 — deterministic, integer-only number profile) — the
//! same helper the embedded provider uses to derive the SCID and entry
//! hashes, so validation and production stay in lockstep.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, VerifyingKey};
use salvo::http::StatusCode;
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};

#[cfg(test)]
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];
const WEBVH_SCID_PLACEHOLDER: &str = "{SCID}";
pub const WEBVH_DEGRADED_NO_WITNESS_MAX_SECS: i64 = 24 * 60 * 60;

/// Resolve the effective `degraded_no_witness` window (identity-did.md §4.2.1).
///
/// Defaults to the 24h spec ceiling. `SOLAND_WEBVH_DEGRADED_NO_WITNESS_MAX_SECS`
/// MAY compress it (e.g. to 30s) so e2e tests can exercise the
/// expiry → unresolvable edge without a real 24h wait. Production MUST leave it
/// unset (or at 24h); the env override never raises the window above the spec
/// ceiling — a value above 24h is clamped back to 24h so the compression hook
/// can only tighten, never loosen, the invariant.
pub fn webvh_degraded_no_witness_max_secs() -> i64 {
    std::env::var("SOLAND_WEBVH_DEGRADED_NO_WITNESS_MAX_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.min(WEBVH_DEGRADED_NO_WITNESS_MAX_SECS))
        .unwrap_or(WEBVH_DEGRADED_NO_WITNESS_MAX_SECS)
}

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
}

/// Stable error envelope for webvh validation failures. Maps to the
/// canonical soland `AppError` via `From`, so call-sites can `?` it like
/// any other typed handler error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebvhValidationError {
    /// The entry's own versionId hash does not match the canonical hash of
    /// its content anchored on the accepted predecessor.
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
    /// A witness threshold was configured but not enough distinct valid
    /// witnesses signed the entry.
    WitnessQuorumNotMet {
        at_index: usize,
        required: usize,
        valid: usize,
    },
    /// A witnessless / under-witnessed non-rotation entry stayed in
    /// degraded mode longer than the allowed 24h window.
    WitnessEvidenceExpired {
        at_index: usize,
        age_secs: i64,
        max_secs: i64,
    },
    /// Key rotation is a high-risk DID operation and cannot use
    /// degraded_no_witness.
    RotationWitnessQuorumMissing {
        at_index: usize,
        required: usize,
        valid: usize,
    },
    /// A rotation entry was not authorised by any accepted path: it carried
    /// neither a valid signature from the previous entry's `updateKeys`
    /// (normal controller rotation) nor a valid recovery-key signature
    /// (genesis-declared emergency recovery key). Spec: identity-did.md §7
    /// (controller proof) + key-management.md §3.3 (recovery key path).
    RotationNotAuthorized { at_index: usize, reason: String },
    /// An organization rotation entry did not satisfy the genesis-declared
    /// governance threshold: fewer than `required` distinct valid proofs from
    /// the eligible governance methods signed the entry. Single-sig
    /// submissions on an N-of-M org DID fail closed here. Spec:
    /// identity-did.md §8.1–§8.2.
    GovernanceQuorumNotMet {
        at_index: usize,
        required: usize,
        valid: usize,
    },
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
            Self::WitnessQuorumNotMet { .. } => "webvh_witness_quorum_not_met",
            Self::WitnessEvidenceExpired { .. } => "webvh_witness_evidence_expired",
            Self::RotationWitnessQuorumMissing { .. } => "webvh_rotation_witness_quorum_missing",
            Self::RotationNotAuthorized { .. } => "webvh_rotation_not_authorized",
            Self::GovernanceQuorumNotMet { .. } => "webvh_governance_quorum_not_met",
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
            | Self::WitnessQuorumNotMet { .. }
            | Self::WitnessEvidenceExpired { .. }
            | Self::RotationWitnessQuorumMissing { .. }
            | Self::GovernanceQuorumNotMet { .. }
            | Self::EmptyLog
            | Self::MalformedEntry { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            Self::WitnessSignatureInvalid { .. } | Self::RotationNotAuthorized { .. } => {
                StatusCode::UNAUTHORIZED
            }
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
            Self::WitnessQuorumNotMet {
                at_index,
                required,
                valid,
            } => format!(
                "did:webvh witness quorum not met at index {at_index}: required {required}, valid {valid}"
            ),
            Self::WitnessEvidenceExpired {
                at_index,
                age_secs,
                max_secs,
            } => format!(
                "did:webvh witness evidence expired at index {at_index}: age {age_secs}s exceeds {max_secs}s"
            ),
            Self::RotationWitnessQuorumMissing {
                at_index,
                required,
                valid,
            } => format!(
                "did:webvh rotation witness quorum missing at index {at_index}: required {required}, valid {valid}"
            ),
            Self::RotationNotAuthorized { at_index, reason } => {
                format!("did:webvh rotation at index {at_index} is not authorized: {reason}")
            }
            Self::GovernanceQuorumNotMet {
                at_index,
                required,
                valid,
            } => format!(
                "did:webvh governance quorum not met at index {at_index}: required {required}, valid {valid}"
            ),
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
/// "`did.jsonl` history (SCID + entry hash chain + controller proof)".
/// Per DIF did:webvh v1.0, `versionId = "<seq>-<hash>"` where the hash is
/// the bare base58btc sha256 multihash over the canonical JSON of the
/// entry with `proof` removed and `versionId` set to the predecessor
/// anchor (the SCID for the genesis entry, the previous `versionId`
/// otherwise). Matches the helper used during write in `did.rs`.
pub fn validate_log_chain(log: &[WebvhLogEntry]) -> Result<(), WebvhValidationError> {
    if log.is_empty() {
        return Err(WebvhValidationError::EmptyLog);
    }
    let mut previous_version_time = entry_version_time(&log[0], 0)?;
    // Genesis check — versionId hash must equal canonical hash of the
    // stripped entry anchored on its SCID.
    let genesis_version_id =
        log[0]
            .version_id()
            .ok_or_else(|| WebvhValidationError::MalformedEntry {
                at_index: 0,
                reason: "missing versionId".to_owned(),
            })?;
    let (genesis_seq, genesis_hash) = split_version_id(genesis_version_id).ok_or_else(|| {
        WebvhValidationError::MalformedEntry {
            at_index: 0,
            reason: "versionId must be \"<seq>-<hash>\"".to_owned(),
        }
    })?;
    if genesis_seq != 1 {
        return Err(WebvhValidationError::MalformedEntry {
            at_index: 0,
            reason: "genesis versionId sequence must be 1".to_owned(),
        });
    }
    // The genesis entry-hash preimage anchors on the SCID.
    let genesis_scid = log[0]
        .payload
        .pointer("/parameters/scid")
        .and_then(Value::as_str)
        .ok_or_else(|| WebvhValidationError::MalformedEntry {
            at_index: 0,
            reason: "genesis entry must declare parameters.scid".to_owned(),
        })?;
    let recomputed_genesis =
        webvh_entry_hash_multibase(&log[0].payload, genesis_scid).map_err(|reason| {
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
        let current_version_time = entry_version_time(current, index)?;
        if current_version_time <= previous_version_time {
            return Err(WebvhValidationError::MalformedEntry {
                at_index: index,
                reason: "versionTime must advance strictly across the accepted history".to_owned(),
            });
        }
        previous_version_time = current_version_time;
        if let Some(scid) = current
            .payload
            .pointer("/parameters/scid")
            .and_then(Value::as_str)
            && scid != genesis_scid
        {
            return Err(WebvhValidationError::MalformedEntry {
                at_index: index,
                reason: "parameters.scid cannot change after inception".to_owned(),
            });
        }
        let prev_version_id =
            prev.version_id()
                .ok_or_else(|| WebvhValidationError::MalformedEntry {
                    at_index: index - 1,
                    reason: "missing versionId".to_owned(),
                })?;
        // did:webvh v1.0 carries no separate previousVersionId field. Its
        // native chain link is the current entry hash recomputed after
        // replacing versionId with the accepted predecessor's versionId.
        let current_version_id =
            current
                .version_id()
                .ok_or_else(|| WebvhValidationError::MalformedEntry {
                    at_index: index,
                    reason: "missing versionId".to_owned(),
                })?;
        let (previous_seq, _) = split_version_id(prev_version_id).ok_or_else(|| {
            WebvhValidationError::MalformedEntry {
                at_index: index - 1,
                reason: "versionId must be \"<seq>-<hash>\"".to_owned(),
            }
        })?;
        let (current_seq, current_hash) =
            split_version_id(current_version_id).ok_or_else(|| {
                WebvhValidationError::MalformedEntry {
                    at_index: index,
                    reason: "versionId must be \"<seq>-<hash>\"".to_owned(),
                }
            })?;
        let expected_seq =
            previous_seq
                .checked_add(1)
                .ok_or_else(|| WebvhValidationError::MalformedEntry {
                    at_index: index,
                    reason: "versionId sequence overflow".to_owned(),
                })?;
        if current_seq != expected_seq {
            return Err(WebvhValidationError::MalformedEntry {
                at_index: index,
                reason: format!(
                    "versionId sequence must advance exactly once from {previous_seq} to {}",
                    expected_seq
                ),
            });
        }
        let recomputed =
            webvh_entry_hash_multibase(&current.payload, prev_version_id).map_err(|reason| {
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

fn entry_version_time(
    entry: &WebvhLogEntry,
    at_index: usize,
) -> Result<chrono::DateTime<chrono::FixedOffset>, WebvhValidationError> {
    let version_time = entry
        .payload
        .get("versionTime")
        .and_then(Value::as_str)
        .ok_or_else(|| WebvhValidationError::MalformedEntry {
            at_index,
            reason: "versionTime is required".to_owned(),
        })?;
    chrono::DateTime::parse_from_rfc3339(version_time).map_err(|_| {
        WebvhValidationError::MalformedEntry {
            at_index,
            reason: "versionTime must be an RFC3339 timestamp".to_owned(),
        }
    })
}

/// Derive the SCID a DID claims, from its genesis log entry.
///
/// The DIF didwebvh v1.0 spec defines the SCID as the bare base58btc
/// sha256 multihash of the canonical JSON of the preliminary log entry:
/// all SCID occurrences replaced by the `{SCID}` placeholder, `proof`
/// removed, and `versionId` set to the bare `{SCID}` placeholder. We
/// rebuild that skeleton from the genesis entry — which is what the
/// embedded provider also does at write time (see `derive_webvh_scid`
/// in `did.rs`).
pub fn derive_scid_from_genesis(genesis: &WebvhLogEntry) -> Result<String, WebvhValidationError> {
    let skeleton = scid_skeleton_from_genesis(&genesis.payload).map_err(|reason| {
        WebvhValidationError::MalformedEntry {
            at_index: 0,
            reason,
        }
    })?;
    let canonical = arkret_core::canonical::canonical_json_bytes(&skeleton).map_err(|error| {
        WebvhValidationError::MalformedEntry {
            at_index: 0,
            reason: error.to_string(),
        }
    })?;
    Ok(sha256_multihash_base58btc(&canonical))
}

pub(crate) fn derive_webvh_scid_from_skeleton(skeleton: &Value) -> Result<String, String> {
    let canonical = arkret_core::canonical::canonical_json_bytes(skeleton)
        .map_err(|error| error.to_string())?;
    Ok(sha256_multihash_base58btc(&canonical))
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

pub fn verify_log_subject(did: &str, log: &[WebvhLogEntry]) -> Result<(), WebvhValidationError> {
    for (index, entry) in log.iter().enumerate() {
        if entry.payload.pointer("/state/id").and_then(Value::as_str) != Some(did) {
            return Err(WebvhValidationError::MalformedEntry {
                at_index: index,
                reason: "state.id must equal the resolved did:webvh subject".to_owned(),
            });
        }
    }
    Ok(())
}

/// Verify at least one witness signature on a log entry, when one is
/// present. Kept for existing call sites; quorum-aware resolution uses
/// [`validate_witness_policy_for_log`].
#[cfg(test)]
pub fn verify_witness_signature(
    entry: &WebvhLogEntry,
    accepted_witness_keys: &[String],
) -> Result<(), WebvhValidationError> {
    verify_witness_quorum(entry, accepted_witness_keys, 1).map(|_| ())
}

/// Validate every configured witness policy in a did:webvh log.
///
/// Policy is read from `parameters.witnesses`, `parameters.witnessQuorum`,
/// `parameters.witness_threshold`, or `parameters.witnessThreshold`.
/// No configured witness policy means the deployment has opted out of
/// witness enforcement for that DID. When a policy exists, non-rotation
/// entries may be temporarily under-witnessed for 24h; rotation entries
/// fail closed immediately because they change DID control.
pub fn validate_witness_policy_for_log(
    log: &[WebvhLogEntry],
    now_unix_secs: i64,
) -> Result<(), WebvhValidationError> {
    validate_witness_policy_for_log_with_window(
        log,
        now_unix_secs,
        webvh_degraded_no_witness_max_secs(),
    )
}

/// Window-parameterised variant of [`validate_witness_policy_for_log`].
///
/// `degraded_max_secs` is the effective `degraded_no_witness` ceiling
/// (identity-did.md §4.2.1). The public entry point sources it from
/// [`webvh_degraded_no_witness_max_secs`]; tests pass it explicitly.
pub fn validate_witness_policy_for_log_with_window(
    log: &[WebvhLogEntry],
    now_unix_secs: i64,
    degraded_max_secs: i64,
) -> Result<(), WebvhValidationError> {
    let mut policy = WitnessPolicy::default();
    for (index, entry) in log.iter().enumerate() {
        policy.merge_from_entry(entry);
        if policy.required_threshold == 0 {
            continue;
        }
        let valid = verify_witness_quorum(
            entry,
            &policy.accepted_witness_keys,
            policy.required_threshold,
        )?;
        if valid >= policy.required_threshold {
            continue;
        }
        if index > 0 && is_rotation_entry(&log[index - 1], entry) {
            return Err(WebvhValidationError::RotationWitnessQuorumMissing {
                at_index: index,
                required: policy.required_threshold,
                valid,
            });
        }
        let age_secs = entry_age_secs(entry, now_unix_secs).ok_or_else(|| {
            WebvhValidationError::MalformedEntry {
                at_index: index,
                reason: "versionTime is required for degraded_no_witness window".to_owned(),
            }
        })?;
        if age_secs > degraded_max_secs {
            return Err(WebvhValidationError::WitnessEvidenceExpired {
                at_index: index,
                age_secs,
                max_secs: degraded_max_secs,
            });
        }
    }
    Ok(())
}

/// Validate that every rotation entry in a `did:webvh` log was authorised by
/// an accepted control path. A rotation entry (one that changes `updateKeys`
/// or the document's control keys) MUST activate the one precommitted update
/// authority and be signed by that authority. Organization governance, when
/// configured, is an additional quorum requirement rather than an alternative
/// control path:
///
/// 1. **pre-rotated controller** — the entry activates exactly one update key, its multikey hash is
///    committed by the previous entry's `nextKeyHashes`, and that newly active authority signs the
///    entry.
/// 2. **organization governance quorum** — when the genesis declares an `application-level
///    multi-proof` governance threshold (`parameters.governance.threshold` + eligible methods), at
///    least `threshold` distinct valid `proof[]` from the eligible governance methods MUST sign the
///    rotation. A single-sig submission on an N-of-M org DID fails closed. Spec: identity-did.md
///    §8.1–§8.2.
///
/// Witness quorum (history visibility) is validated separately by
/// [`validate_witness_policy_for_log`]; this function validates control
/// authorisation (who may change the DID), which the spec keeps distinct from
/// witnessing (§8.1: witnesses attest that the log history was visible,
/// while the quorum attests that the change was governance-authorized).
pub fn validate_rotation_authorization_for_log(
    log: &[WebvhLogEntry],
) -> Result<(), WebvhValidationError> {
    if log.is_empty() {
        return Err(WebvhValidationError::EmptyLog);
    }
    for (index, entry) in log.iter().enumerate() {
        if entry
            .payload
            .pointer("/parameters/method")
            .and_then(Value::as_str)
            != Some("did:webvh:1.0")
        {
            return Err(WebvhValidationError::MalformedEntry {
                at_index: index,
                reason: "parameters.method must be did:webvh:1.0".to_owned(),
            });
        }
    }
    let governance = GovernancePolicy::from_genesis(&log[0]);
    let genesis_keys = update_keys_of(&log[0]);
    if genesis_keys.len() != 1 {
        return Err(WebvhValidationError::RotationNotAuthorized {
            at_index: 0,
            reason: "genesis entry must activate exactly one update key".to_owned(),
        });
    }
    validate_active_controller_proof(&log[0])?;
    let mut activated_update_keys = genesis_keys.into_iter().collect::<BTreeSet<_>>();
    validate_next_root_commitment(&log[0], 0, &activated_update_keys)?;
    for index in 1..log.len() {
        let previous = &log[index - 1];
        let current = &log[index];
        // An organization governance policy adds a quorum gate. It never
        // substitutes for the precommitted active update authority.
        if let Some(policy) = &governance {
            let valid = count_distinct_valid_entry_proofs(current, &policy.eligible_methods)?;
            if valid < policy.threshold {
                return Err(WebvhValidationError::GovernanceQuorumNotMet {
                    at_index: index,
                    required: policy.threshold,
                    valid,
                });
            }
        }
        let current_keys = update_keys_of(current);
        if current_keys.len() != 1 {
            return Err(WebvhValidationError::RotationNotAuthorized {
                at_index: index,
                reason: "rotation entry must activate exactly one update key".to_owned(),
            });
        }
        if activated_update_keys.contains(&current_keys[0]) {
            return Err(WebvhValidationError::RotationNotAuthorized {
                at_index: index,
                reason: "rotation reuses a previously activated update key".to_owned(),
            });
        }
        let expected = sha256_multihash_base58btc(current_keys[0].as_bytes());
        let previous_commitments = next_key_hashes_of(previous);
        let committed = previous_commitments.len() == 1 && previous_commitments[0] == expected;
        if !committed {
            return Err(WebvhValidationError::RotationNotAuthorized {
                at_index: index,
                reason: "new active update key is not committed by previous nextKeyHashes"
                    .to_owned(),
            });
        }
        validate_active_controller_proof(current).map_err(|error| {
            WebvhValidationError::RotationNotAuthorized {
                at_index: index,
                reason: error.to_string(),
            }
        })?;
        activated_update_keys.insert(current_keys[0].clone());
        validate_next_root_commitment(current, index, &activated_update_keys)?;
    }
    Ok(())
}

fn validate_next_root_commitment(
    entry: &WebvhLogEntry,
    at_index: usize,
    activated_update_keys: &BTreeSet<String>,
) -> Result<(), WebvhValidationError> {
    let next_hashes = next_key_hashes_of(entry);
    if next_hashes.len() != 1 {
        return Err(WebvhValidationError::RotationNotAuthorized {
            at_index,
            reason: "entry must commit exactly one next update key".to_owned(),
        });
    }
    if activated_update_keys
        .iter()
        .any(|key| sha256_multihash_base58btc(key.as_bytes()) == next_hashes[0])
    {
        return Err(WebvhValidationError::RotationNotAuthorized {
            at_index,
            reason: "entry nextKeyHashes reuses an already activated update key".to_owned(),
        });
    }
    Ok(())
}

/// Count distinct verification methods in an entry's `proof[]` array whose key
/// is in `accepted_keys` AND whose signature verifies over the proof-stripped
/// canonical entry. Any *present* proof whose key is in `accepted_keys` but
/// whose signature is invalid is a hard failure (you cannot launder a forged
/// controller/governance signature into a "missing proof").
fn count_distinct_valid_entry_proofs(
    entry: &WebvhLogEntry,
    accepted_keys: &[String],
) -> Result<usize, WebvhValidationError> {
    let Some(proofs) = entry.payload.get("proof").and_then(Value::as_array) else {
        return Ok(0);
    };
    let mut seen = std::collections::BTreeSet::new();
    for proof in proofs.iter().filter_map(Value::as_object) {
        let key = entry_proof_key(proof);
        if accepted_keys.iter().all(|accepted| accepted != &key) {
            continue;
        }
        verify_entry_proof(entry, proof)?;
        seen.insert(key);
    }
    Ok(seen.len())
}

/// Verify that a log entry is signed by the update authority activated by
/// that same entry. Arkret's pre-rotation profile never treats a previous root
/// as the active authority for the new entry.
pub fn validate_active_controller_proof(entry: &WebvhLogEntry) -> Result<(), WebvhValidationError> {
    let update_keys = update_keys_of(entry);
    if update_keys.len() != 1 {
        return Err(WebvhValidationError::RotationNotAuthorized {
            at_index: 0,
            reason: "entry must activate exactly one update key".to_owned(),
        });
    }
    if count_distinct_valid_entry_proofs(entry, &update_keys)? != 1 {
        return Err(WebvhValidationError::RotationNotAuthorized {
            at_index: 0,
            reason: "entry is not signed by its active update authority".to_owned(),
        });
    }
    Ok(())
}

pub fn active_update_verification_methods(entry: &WebvhLogEntry) -> Vec<String> {
    update_keys_of(entry)
        .into_iter()
        .map(|multikey| format!("did:key:{multikey}#{multikey}"))
        .collect()
}

/// Verify a single `proof[]` object signs the proof-stripped canonical entry
/// under `eddsa-jcs-2022`. Controller proofs intentionally keep `witness`
/// and `versionId`, matching the embedded provider and coauth's
/// `soland_webvh::build_proof`.
fn verify_entry_proof(
    entry: &WebvhLogEntry,
    proof: &serde_json::Map<String, Value>,
) -> Result<(), WebvhValidationError> {
    let signing_input =
        webvh_eddsa_jcs_2022_signing_input(&entry.payload, proof).map_err(|reason| {
            WebvhValidationError::RotationNotAuthorized {
                at_index: 0,
                reason,
            }
        })?;
    let key = entry_proof_key(proof);
    let public_key = decode_ed25519_public_key(&key).map_err(|reason| {
        WebvhValidationError::RotationNotAuthorized {
            at_index: 0,
            reason,
        }
    })?;
    let signature = decode_webvh_signature(
        proof
            .get("proofValue")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )
    .map_err(|reason| WebvhValidationError::RotationNotAuthorized {
        at_index: 0,
        reason,
    })?;
    public_key
        .verify_strict(&signing_input, &signature)
        .map_err(|_| WebvhValidationError::RotationNotAuthorized {
            at_index: 0,
            reason: "rotation proof signature is invalid".to_owned(),
        })
}

/// Build the `eddsa-jcs-2022` Data Integrity signing input shared by WebVH
/// inception and rotation proof verification:
/// `SHA-256(JCS(proofConfig)) || SHA-256(JCS(document))`.
///
/// `proofConfig` is the proof without `proofValue`; `document` is the log
/// entry without its `proof` array. This mirrors the SDK's canonical WebVH
/// verifier and keeps both Soland proof admission paths byte-identical.
fn webvh_eddsa_jcs_2022_signing_input(
    entry: &Value,
    proof: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    if proof.get("type").and_then(Value::as_str) != Some("DataIntegrityProof") {
        return Err("proof type must be DataIntegrityProof".to_owned());
    }
    if proof.get("cryptosuite").and_then(Value::as_str) != Some("eddsa-jcs-2022") {
        return Err("proof cryptosuite must be eddsa-jcs-2022".to_owned());
    }
    if proof.get("proofPurpose").and_then(Value::as_str) != Some("assertionMethod") {
        return Err("proofPurpose must be assertionMethod".to_owned());
    }

    let mut proof_config = Value::Object(proof.clone());
    if let Value::Object(properties) = &mut proof_config {
        properties.remove("proofValue");
    }
    let mut document = entry.clone();
    if let Value::Object(properties) = &mut document {
        properties.remove("proof");
    }
    let proof_config = arkret_core::canonical::canonical_json_bytes(&proof_config)
        .map_err(|error| format!("webvh proofConfig canonicalization failed: {error}"))?;
    let document = arkret_core::canonical::canonical_json_bytes(&document)
        .map_err(|error| format!("webvh proof document canonicalization failed: {error}"))?;

    let mut signing_input = Vec::with_capacity(64);
    signing_input.extend_from_slice(&arkret_core::canonical::sha256_bytes(&proof_config));
    signing_input.extend_from_slice(&arkret_core::canonical::sha256_bytes(&document));
    Ok(signing_input)
}

/// Extract the multibase key a `proof[]` object signs with — the fragment
/// after `#` in `verificationMethod` (matching the `did:key:<mb>#<mb>` shape
/// the embedded provider / coauth emit).
fn entry_proof_key(proof: &serde_json::Map<String, Value>) -> String {
    let verification_method = proof
        .get("verificationMethod")
        .and_then(Value::as_str)
        .unwrap_or_default();
    verification_method
        .rsplit_once('#')
        .map(|(_, fragment)| fragment)
        .unwrap_or(verification_method)
        .to_owned()
}

fn update_keys_of(entry: &WebvhLogEntry) -> Vec<String> {
    entry
        .payload
        .pointer("/parameters/updateKeys")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn next_key_hashes_of(entry: &WebvhLogEntry) -> Vec<String> {
    entry
        .payload
        .pointer("/parameters/nextKeyHashes")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

struct GovernancePolicy {
    threshold: usize,
    eligible_methods: Vec<String>,
}

impl GovernancePolicy {
    /// Read an `application-level multi-proof` governance policy from the
    /// genesis `parameters.governance` block (identity-did.md §8). Returns
    /// `None` when no governance threshold is declared (ordinary single-key
    /// principal DID).
    fn from_genesis(genesis: &WebvhLogEntry) -> Option<Self> {
        let governance = genesis.payload.pointer("/parameters/governance")?;
        let threshold = governance
            .pointer("/threshold/required")
            .or_else(|| governance.get("threshold"))
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| *value > 0)?;
        let eligible_methods = governance
            .pointer("/threshold/eligible_methods")
            .or_else(|| governance.get("eligible_methods"))
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|value| {
                        value
                            .rsplit_once('#')
                            .map(|(_, fragment)| fragment)
                            .unwrap_or(value)
                            .to_owned()
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            threshold,
            eligible_methods,
        })
    }
}

/// Verify all witness proofs on an entry and return the number of
/// distinct valid verification methods. Invalid signatures remain hard
/// failures; missing or under-threshold signatures return their valid
/// count so the caller can apply the degraded-window rules.
pub fn verify_witness_quorum(
    entry: &WebvhLogEntry,
    accepted_witness_keys: &[String],
    required_threshold: usize,
) -> Result<usize, WebvhValidationError> {
    if required_threshold == 0 {
        return Ok(0);
    }
    let Some(proofs) = entry.payload.get("witness").and_then(Value::as_array) else {
        return Ok(0);
    };
    let mut seen = std::collections::BTreeSet::new();
    for proof in proofs.iter().filter_map(Value::as_object) {
        let verification_method = proof
            .get("verificationMethod")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        verify_one_witness_proof(entry, proof, accepted_witness_keys)?;
        seen.insert(verification_method);
    }
    Ok(seen.len())
}

fn verify_one_witness_proof(
    entry: &WebvhLogEntry,
    proof: &serde_json::Map<String, Value>,
    accepted_witness_keys: &[String],
) -> Result<(), WebvhValidationError> {
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
        map.remove("versionId");
    }
    let payload =
        arkret_core::canonical::canonical_json_bytes(&canonical_entry).map_err(|error| {
            WebvhValidationError::WitnessSignatureInvalid {
                reason: error.to_string(),
            }
        })?;
    public_key.verify_strict(&payload, &signature).map_err(|_| {
        WebvhValidationError::WitnessSignatureInvalid {
            reason: "ed25519 verification failed".to_owned(),
        }
    })
}

pub(crate) fn verify_webvh_log_proof(entry: &Value) -> Result<(), String> {
    let proof = entry
        .get("proof")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_object)
        .ok_or_else(|| "entry must include proof[0]".to_owned())?;
    let signing_input = webvh_eddsa_jcs_2022_signing_input(entry, proof)?;
    let verification_method = proof
        .get("verificationMethod")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let public_key_multibase = verification_method
        .rsplit_once('#')
        .map(|(_, fragment)| fragment)
        .unwrap_or(verification_method);
    let update_keys = entry
        .pointer("/parameters/updateKeys")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    if !update_keys.contains(&public_key_multibase) {
        return Err("proof verificationMethod must reference updateKeys[0]".to_owned());
    }
    let public_key = decode_ed25519_public_key(public_key_multibase)?;
    let signature = decode_webvh_signature(
        proof
            .get("proofValue")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )?;
    public_key
        .verify_strict(&signing_input, &signature)
        .map_err(|_| "webvh log proof signature is invalid".to_owned())
}

#[derive(Default)]
struct WitnessPolicy {
    required_threshold: usize,
    accepted_witness_keys: Vec<String>,
}

impl WitnessPolicy {
    fn merge_from_entry(&mut self, entry: &WebvhLogEntry) {
        let parameters = entry.payload.get("parameters").unwrap_or(&Value::Null);
        if let Some(threshold) = witness_threshold(parameters) {
            self.required_threshold = threshold;
        }
        for key in witness_keys(parameters) {
            if !self.accepted_witness_keys.iter().any(|seen| seen == &key) {
                self.accepted_witness_keys.push(key);
            }
        }
        if self.required_threshold == 0 && !self.accepted_witness_keys.is_empty() {
            self.required_threshold = 1;
        }
    }
}

fn witness_threshold(parameters: &Value) -> Option<usize> {
    parameters
        .get("witness_threshold")
        .or_else(|| parameters.get("witnessThreshold"))
        .or_else(|| parameters.pointer("/witnesses/threshold"))
        .or_else(|| parameters.pointer("/witnesses/threshold_k"))
        .or_else(|| parameters.pointer("/witnesses/k"))
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
}

fn witness_keys(parameters: &Value) -> Vec<String> {
    let Some(witnesses) = parameters.get("witnesses") else {
        return Vec::new();
    };
    match witnesses {
        Value::Array(items) => items.iter().filter_map(witness_key).collect(),
        Value::Object(object) => object
            .get("keys")
            .or_else(|| object.get("trusted_witnesses"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(witness_key)
            .collect(),
        _ => Vec::new(),
    }
}

fn witness_key(value: &Value) -> Option<String> {
    match value {
        Value::String(value) if !value.trim().is_empty() => Some(value.trim().to_owned()),
        Value::Object(object) => [
            "publicKeyMultibase",
            "public_key_multibase",
            "verificationMethod",
            "id",
            "key",
        ]
        .iter()
        .find_map(|field| object.get(*field).and_then(Value::as_str))
        .map(|value| {
            value
                .rsplit_once('#')
                .map(|(_, fragment)| fragment)
                .unwrap_or(value)
                .to_owned()
        }),
        _ => None,
    }
}

fn is_rotation_entry(previous: &WebvhLogEntry, current: &WebvhLogEntry) -> bool {
    previous.payload.pointer("/parameters/updateKeys")
        != current.payload.pointer("/parameters/updateKeys")
        || previous.payload.pointer("/state/verificationMethod")
            != current.payload.pointer("/state/verificationMethod")
        || previous.payload.pointer("/state/authentication")
            != current.payload.pointer("/state/authentication")
}

fn entry_age_secs(entry: &WebvhLogEntry, now_unix_secs: i64) -> Option<i64> {
    let version_time = entry.payload.get("versionTime").and_then(Value::as_str)?;
    let parsed = chrono::DateTime::parse_from_rfc3339(version_time).ok()?;
    Some(now_unix_secs.saturating_sub(parsed.timestamp()).max(0))
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

/// Compute the DIF did:webvh v1.0 entry hash. `prev_anchor` is the
/// predecessor anchor: the SCID for the inception entry, or the previous
/// entry's `versionId` for every subsequent entry.
pub(crate) fn webvh_entry_hash_multibase(
    entry: &Value,
    prev_anchor: &str,
) -> Result<String, String> {
    let stripped = strip_webvh_entry_for_hash(entry, prev_anchor);
    let canonical = arkret_core::canonical::canonical_json_bytes(&stripped)
        .map_err(|error| error.to_string())?;
    Ok(sha256_multihash_base58btc(&canonical))
}

/// Build the did:webvh v1.0 entry-hash preimage: drop `proof[]` and set
/// `versionId` to the predecessor anchor.
pub(crate) fn strip_webvh_entry_for_hash(entry: &Value, prev_anchor: &str) -> Value {
    let mut stripped = entry.clone();
    if let Value::Object(map) = &mut stripped {
        map.remove("proof");
        map.insert(
            "versionId".to_owned(),
            Value::String(prev_anchor.to_owned()),
        );
    }
    stripped
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
    // Restore the placeholder versionId shape so the skeleton matches the
    // did:webvh v1.0 preliminary log entry — the bare `{SCID}` placeholder.
    let mut skeleton: Value = serde_json::from_str(&substituted).map_err(|e| e.to_string())?;
    if let Value::Object(map) = &mut skeleton {
        map.insert("versionId".to_owned(), json!(WEBVH_SCID_PLACEHOLDER));
    }
    Ok(skeleton)
}

/// `base58btc(0x12 0x20 || sha256(bytes))` — bare base58btc, NO multibase
/// `z` prefix, per DIF did:webvh v1.0 (SCIDs and entry hashes are 46-char
/// `Qm…` strings; multibase `z` applies to keys/signatures only).
pub(crate) fn sha256_multihash_base58btc(bytes: &[u8]) -> String {
    arkret_core::sha256_multihash_base58btc(bytes)
}

pub(crate) fn decode_ed25519_public_key(value: &str) -> Result<VerifyingKey, String> {
    let key_bytes = arkret_core::decode_ed25519_multibase(value)
        .map_err(|error| format!("public key must be base58btc ed25519-pub multibase: {error}"))?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| "invalid ed25519 public key".to_owned())
}

pub(crate) fn decode_webvh_signature(value: &str) -> Result<Signature, String> {
    let signature_bytes = arkret_core::decode_ed25519_signature_multibase(value)
        .map_err(|error| format!("invalid ed25519 proofValue: {error}"))?;
    Ok(Signature::from_bytes(&signature_bytes))
}

// --- SEC-01: verifiable resolver degraded/health diagnostic signal ---
#[cfg(test)]
mod tests {
    use ed25519_dalek::{PUBLIC_KEY_LENGTH, Signer, SigningKey};
    use rand::RngExt;

    use super::*;

    fn fresh_signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
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

    fn sdk_canonical_principal_inception() -> (Value, SigningKey) {
        let endpoint = url::Url::parse("https://principal.example/").unwrap();
        let aliases = vec!["acct:alice@example.com".to_owned()];
        let root_seed = [0x11; 32];
        let root_signing = SigningKey::from_bytes(&root_seed);
        let next_root = SigningKey::from_bytes(&[0x22; 32]);
        let next_root_multibase = encode_pubkey_multibase(&next_root.verifying_key());
        let input = arkret_signatures::webvh::PrincipalInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "alice",
            also_known_as: &aliases,
            version_time: chrono::DateTime::parse_from_rfc3339("2026-07-15T00:00:00Z")
                .unwrap()
                .to_utc(),
            root_seed: &root_seed,
            next_root_public_key_multibase: &next_root_multibase,
            enrollment:
                arkret_signatures::webvh::PrincipalEnrollmentDelegation::ExternalAuthority {
                    authority_did: "did:web:coauth.example",
                },
        };
        let prepared = arkret_signatures::webvh::prepare_principal_inception(&input)
            .expect("SDK canonical principal inception");
        (prepared.log_entry, root_signing)
    }

    fn assert_controller_and_inception_verifiers_reject(entry: Value) {
        assert!(
            verify_webvh_log_proof(&entry).is_err(),
            "inception proof verifier must reject"
        );
        assert!(
            validate_active_controller_proof(&WebvhLogEntry::new(entry)).is_err(),
            "active-controller proof verifier must reject"
        );
    }

    #[test]
    fn sdk_canonical_principal_inception_proof_is_accepted() {
        let (entry, _) = sdk_canonical_principal_inception();
        verify_webvh_log_proof(&entry).expect("SDK inception proof must verify");
        validate_active_controller_proof(&WebvhLogEntry::new(entry))
            .expect("SDK inception active-controller proof must verify");
    }

    #[test]
    fn legacy_raw_jcs_webvh_signature_is_rejected() {
        let (mut entry, root_signing) = sdk_canonical_principal_inception();
        let mut document = entry.clone();
        document
            .as_object_mut()
            .expect("entry object")
            .remove("proof");
        let canonical = arkret_core::canonical::canonical_json_bytes(&document).unwrap();
        let legacy_signature = root_signing.sign(&canonical);
        entry["proof"][0]["proofValue"] = json!(encode_sig_multibase(&legacy_signature));

        assert_controller_and_inception_verifiers_reject(entry);
    }

    #[test]
    fn canonical_webvh_proof_rejects_document_tampering() {
        let (mut entry, _) = sdk_canonical_principal_inception();
        entry["state"]["id"] = json!("did:webvh:QmTampered:principal.example:webvh:alice");

        assert_controller_and_inception_verifiers_reject(entry);
    }

    fn witness_proof(entry: &Value, signer: &SigningKey) -> Value {
        let mut signed_entry = entry.clone();
        if let Value::Object(map) = &mut signed_entry {
            map.remove("witness");
            map.remove("proof");
            map.remove("versionId");
        }
        let canonical = arkret_core::canonical::canonical_json_bytes(&signed_entry).unwrap();
        let signature = signer.sign(&canonical);
        let public_key = encode_pubkey_multibase(&signer.verifying_key());
        json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": format!("did:web:witness.example#{public_key}"),
            "proofValue": encode_sig_multibase(&signature),
        })
    }

    /// Build a genesis log entry with a self-consistent SCID + versionId.
    fn build_genesis(update_key_multibase: &str) -> (String, WebvhLogEntry) {
        // 1) Build the SCID-derivation skeleton (placeholder SCID).
        let skeleton = json!({
            "versionId": WEBVH_SCID_PLACEHOLDER,
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
        let canonical = arkret_core::canonical::canonical_json_bytes(&skeleton).unwrap();
        let scid = sha256_multihash_base58btc(&canonical);
        // 2) Substitute the real SCID back in everywhere.
        let text = serde_json::to_string(&skeleton).unwrap();
        let realised: Value =
            serde_json::from_str(&text.replace(WEBVH_SCID_PLACEHOLDER, &scid)).unwrap();
        // 3) Compute the entry's own versionId hash (anchored on the SCID).
        let entry_hash = webvh_entry_hash_multibase(&realised, &scid).unwrap();
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
            "parameters": {
                "scid": scid,
                "method": "did:webvh:1.0",
                "updateKeys": ["z6MkrotatedKey00000000000000000000000000000"],
            },
            "state": {
                "id": format!("did:webvh:{scid}:test.example:webvh:alice"),
            },
        });
        let hash = webvh_entry_hash_multibase(&body, prev.version_id().unwrap()).unwrap();
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
    fn chain_break_detects_entry_hashed_against_forged_predecessor() {
        let signing = fresh_signing_key();
        let pubkey_mb = encode_pubkey_multibase(&signing.verifying_key());
        let (scid, genesis) = build_genesis(&pubkey_mb);
        let mut entry_two = build_entry_two(&genesis, &scid).payload;
        if let Value::Object(map) = &mut entry_two {
            let recomputed = webvh_entry_hash_multibase(
                &Value::Object(map.clone()),
                "1-QmForgedPreviousHash00000000000000000000000",
            )
            .unwrap();
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
        // Sign the witness transcript with the forger key; attach it as if it
        // came from the configured witness.
        let mut forged_payload = entry_body.clone();
        if let Value::Object(map) = &mut forged_payload {
            map.remove("witness");
            map.remove("proof");
            map.remove("versionId");
        }
        let canonical = arkret_core::canonical::canonical_json_bytes(&forged_payload).unwrap();
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

    #[test]
    fn witness_quorum_counts_distinct_valid_signatures() {
        let witness_a = fresh_signing_key();
        let witness_b = fresh_signing_key();
        let witness_c = fresh_signing_key();
        let witness_a_pubkey = encode_pubkey_multibase(&witness_a.verifying_key());
        let witness_b_pubkey = encode_pubkey_multibase(&witness_b.verifying_key());
        let witness_c_pubkey = encode_pubkey_multibase(&witness_c.verifying_key());
        let mut entry_body = json!({
            "versionId": "1-zSomeHash",
            "versionTime": "2026-05-25T00:00:00Z",
            "parameters": {
                "method": "did:webvh:1.0",
                "updateKeys": ["z6MkupdateKey"],
                "witness_threshold": 2,
                "witnesses": [
                    {"publicKeyMultibase": witness_a_pubkey},
                    {"publicKeyMultibase": witness_b_pubkey},
                    {"publicKeyMultibase": witness_c_pubkey}
                ]
            },
        });
        let proof_a = witness_proof(&entry_body, &witness_a);
        let proof_b = witness_proof(&entry_body, &witness_b);
        entry_body["witness"] = json!([proof_a, proof_b]);
        let entry = WebvhLogEntry::new(entry_body);

        let now = chrono::DateTime::parse_from_rfc3339("2026-05-25T00:01:00Z")
            .unwrap()
            .timestamp();
        validate_witness_policy_for_log(&[entry], now)
            .expect("two distinct valid witnesses satisfy threshold");
    }

    #[test]
    fn rotation_without_witness_quorum_fails_closed_inside_degraded_window() {
        let witness_a = encode_pubkey_multibase(&fresh_signing_key().verifying_key());
        let witness_b = encode_pubkey_multibase(&fresh_signing_key().verifying_key());
        let genesis = WebvhLogEntry::new(json!({
            "versionId": "1-zGenesis",
            "versionTime": "2026-05-25T00:00:00Z",
            "parameters": {
                "method": "did:webvh:1.0",
                "updateKeys": ["z6MkoldKey"],
                "witness_threshold": 2,
                "witnesses": [
                    {"publicKeyMultibase": witness_a},
                    {"publicKeyMultibase": witness_b}
                ]
            },
            "state": {"authentication": ["did:webvh:z6mkfixture:example#old"]},
        }));
        let rotation = WebvhLogEntry::new(json!({
            "versionId": "2-zRotation",
            "versionTime": "2026-05-25T00:30:00Z",
            "parameters": {
                "method": "did:webvh:1.0",
                "updateKeys": ["z6MknewKey"],
            },
            "state": {"authentication": ["did:webvh:z6mkfixture:example#new"]},
        }));
        let now = chrono::DateTime::parse_from_rfc3339("2026-05-25T00:40:00Z")
            .unwrap()
            .timestamp();
        let err = validate_witness_policy_for_log(&[genesis, rotation], now)
            .expect_err("rotation cannot use degraded_no_witness");
        match err {
            WebvhValidationError::RotationWitnessQuorumMissing {
                at_index,
                required,
                valid,
            } => {
                assert_eq!(at_index, 1);
                assert_eq!(required, 2);
                assert_eq!(valid, 0);
            }
            other => panic!("expected RotationWitnessQuorumMissing, got {other:?}"),
        }
    }

    #[test]
    fn non_rotation_missing_witness_expires_after_24h() {
        let witness_a = encode_pubkey_multibase(&fresh_signing_key().verifying_key());
        let entry = WebvhLogEntry::new(json!({
            "versionId": "1-zGenesis",
            "versionTime": "2026-05-25T00:00:00Z",
            "parameters": {
                "method": "did:webvh:1.0",
                "updateKeys": ["z6MkoldKey"],
                "witness_threshold": 1,
                "witnesses": [
                    {"publicKeyMultibase": witness_a}
                ]
            },
        }));
        let now = chrono::DateTime::parse_from_rfc3339("2026-05-26T00:00:01Z")
            .unwrap()
            .timestamp();
        let err = validate_witness_policy_for_log(&[entry], now)
            .expect_err("degraded_no_witness expires after 24h");
        match err {
            WebvhValidationError::WitnessEvidenceExpired {
                at_index, max_secs, ..
            } => {
                assert_eq!(at_index, 0);
                assert_eq!(max_secs, WEBVH_DEGRADED_NO_WITNESS_MAX_SECS);
            }
            other => panic!("expected WitnessEvidenceExpired, got {other:?}"),
        }
    }
}
