//! Soland adapters for the SDK-owned did:webvh verifier.
//!
//! Cryptographic construction and verification live in `arkret-identity`.
//! This module only preserves Soland's HTTP error mapping and the small
//! `WebvhLogEntry` wrapper used by routing code.

use ed25519_dalek::VerifyingKey;
use salvo::http::StatusCode;
use serde_json::Value;
use soland_http::error::{AppError, ErrorCode};

#[derive(Clone, Debug)]
pub struct WebvhLogEntry {
    pub payload: Value,
}

impl WebvhLogEntry {
    pub fn new(payload: Value) -> Self {
        Self { payload }
    }

    pub fn version_id(&self) -> Option<&str> {
        self.payload.get("versionId").and_then(Value::as_str)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebvhValidationError {
    ChainBreak {
        at_index: usize,
        expected: String,
        actual: String,
    },
    ScidMismatch {
        in_did: String,
        derived: String,
    },
    WitnessSignatureInvalid {
        reason: String,
    },
    WitnessQuorumNotMet {
        at_index: usize,
        required: usize,
        valid: usize,
    },
    WitnessEvidenceExpired {
        at_index: usize,
        age_secs: i64,
        max_secs: i64,
    },
    RotationWitnessQuorumMissing {
        at_index: usize,
        required: usize,
        valid: usize,
    },
    RotationNotAuthorized {
        at_index: usize,
        reason: String,
    },
    GovernanceQuorumNotMet {
        at_index: usize,
        required: usize,
        valid: usize,
    },
    ResidualScidPlaceholder {
        at_index: usize,
    },
    EmptyLog,
    MalformedEntry {
        at_index: usize,
        reason: String,
    },
}

impl WebvhValidationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ChainBreak { .. } => "webvh_chain_break",
            Self::ScidMismatch { .. } => "webvh_scid_mismatch",
            Self::WitnessSignatureInvalid { .. } => "webvh_witness_proof_invalid",
            Self::WitnessQuorumNotMet { .. } => "webvh_witness_threshold_not_met",
            Self::WitnessEvidenceExpired { .. } => "webvh_witness_evidence_stale",
            Self::RotationWitnessQuorumMissing { .. } => "webvh_witness_threshold_not_met",
            Self::RotationNotAuthorized { .. } => "webvh_rotation_not_authorized",
            Self::GovernanceQuorumNotMet { .. } => "webvh_governance_quorum_not_met",
            Self::ResidualScidPlaceholder { .. } => "param_invalid",
            Self::EmptyLog => "webvh_empty_log",
            Self::MalformedEntry { .. } => "webvh_witness_parameter_malformed",
        }
    }

    pub fn http_status(&self) -> StatusCode {
        match self {
            Self::WitnessSignatureInvalid { .. } | Self::RotationNotAuthorized { .. } => {
                StatusCode::UNAUTHORIZED
            }
            _ => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::ChainBreak {
                at_index,
                expected,
                actual,
            } => format!(
                "did:webvh log chain break at index {at_index}: expected {expected}, got {actual}"
            ),
            Self::ScidMismatch { in_did, derived } => {
                format!("did:webvh SCID mismatch: DID embeds {in_did}, derived {derived}")
            }
            Self::WitnessSignatureInvalid { reason } => {
                format!("did:webvh witness proof invalid: {reason}")
            }
            Self::WitnessQuorumNotMet {
                at_index,
                required,
                valid,
            }
            | Self::RotationWitnessQuorumMissing {
                at_index,
                required,
                valid,
            } => format!(
                "did:webvh witness threshold not met at index {at_index}: required {required}, valid {valid}"
            ),
            Self::WitnessEvidenceExpired {
                at_index,
                age_secs,
                max_secs,
            } => format!(
                "did:webvh witness evidence stale at index {at_index}: age {age_secs}s exceeds {max_secs}s"
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
            Self::ResidualScidPlaceholder { at_index } => format!(
                "did:webvh log entry at index {at_index} retains a literal {{SCID}} placeholder"
            ),
            Self::EmptyLog => "did:webvh log is empty".to_owned(),
            Self::MalformedEntry { at_index, reason } => {
                format!("did:webvh log entry at index {at_index} is malformed: {reason}")
            }
        }
    }
}

impl std::fmt::Display for WebvhValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message())
    }
}

impl std::error::Error for WebvhValidationError {}

impl From<WebvhValidationError> for AppError {
    fn from(error: WebvhValidationError) -> Self {
        let status = error.http_status();
        let code = if status == StatusCode::UNAUTHORIZED {
            ErrorCode::SignatureInvalid
        } else {
            ErrorCode::SchemaViolation
        };
        AppError::new(code, error.message())
            .with_status(status)
            .with_wire_code(error.code())
    }
}

fn did_from_log(log: &[WebvhLogEntry]) -> Result<arkret_wire::DidFullId, WebvhValidationError> {
    let first = log.first().ok_or(WebvhValidationError::EmptyLog)?;
    let did = first
        .payload
        .pointer("/state/id")
        .and_then(Value::as_str)
        .ok_or_else(|| WebvhValidationError::MalformedEntry {
            at_index: 0,
            reason: "state.id is required".to_owned(),
        })?;
    arkret_wire::DidFullId::new(did).map_err(|error| WebvhValidationError::MalformedEntry {
        at_index: 0,
        reason: error.to_string(),
    })
}

fn raw_log(log: &[WebvhLogEntry]) -> Vec<Value> {
    log.iter().map(|entry| entry.payload.clone()).collect()
}

pub fn verify_log_and_witness_bytes(
    did: &arkret_wire::DidFullId,
    did_jsonl: &[u8],
    did_witness_json: &[u8],
) -> Result<arkret_identity::VerifiedDidWebvhWitnessLog, WebvhValidationError> {
    arkret_identity::verify_did_webvh_v1_chain_and_witness_bytes(
        did,
        did_jsonl,
        Some(did_witness_json),
    )
    .map_err(|error| match error {
        arkret_identity::DidWebvhWitnessValidationError::ParameterMalformed(reason) => {
            WebvhValidationError::MalformedEntry {
                at_index: 0,
                reason,
            }
        }
        arkret_identity::DidWebvhWitnessValidationError::ProofsUnavailable { .. } => {
            WebvhValidationError::WitnessQuorumNotMet {
                at_index: 0,
                required: 1,
                valid: 0,
            }
        }
        arkret_identity::DidWebvhWitnessValidationError::ThresholdNotMet {
            required,
            verified,
            ..
        } => WebvhValidationError::WitnessQuorumNotMet {
            at_index: 0,
            required,
            valid: verified,
        },
        arkret_identity::DidWebvhWitnessValidationError::ProofInvalid(reason) => {
            WebvhValidationError::WitnessSignatureInvalid { reason }
        }
        arkret_identity::DidWebvhWitnessValidationError::Log(error) => {
            WebvhValidationError::MalformedEntry {
                at_index: 0,
                reason: error.to_string(),
            }
        }
    })
}

fn verify_sdk_chain(log: &[WebvhLogEntry]) -> Result<(), WebvhValidationError> {
    if let Some(at_index) = log
        .iter()
        .position(|entry| arkret_signatures::webvh::webvh_scid_placeholder_present(&entry.payload))
    {
        return Err(WebvhValidationError::ResidualScidPlaceholder { at_index });
    }
    let did = did_from_log(log)?;
    arkret_identity::verify_did_webvh_v1_chain(&did, &raw_log(log)).map_err(|error| {
        WebvhValidationError::MalformedEntry {
            at_index: 0,
            reason: error.to_string(),
        }
    })?;
    Ok(())
}

pub fn validate_log_chain(log: &[WebvhLogEntry]) -> Result<(), WebvhValidationError> {
    verify_sdk_chain(log)
}

pub fn derive_scid_from_genesis(genesis: &WebvhLogEntry) -> Result<String, WebvhValidationError> {
    arkret_identity::derive_did_webvh_scid(&genesis.payload).map_err(|error| {
        WebvhValidationError::MalformedEntry {
            at_index: 0,
            reason: error.to_string(),
        }
    })
}

pub fn scid_from_did(did: &str) -> Option<&str> {
    did.strip_prefix("did:webvh:")?.split(':').next()
}

pub fn verify_scid_against_did(
    did: &str,
    genesis: &WebvhLogEntry,
) -> Result<(), WebvhValidationError> {
    let in_did = scid_from_did(did).unwrap_or_default();
    let derived = derive_scid_from_genesis(genesis)?;
    if in_did != derived {
        return Err(WebvhValidationError::ScidMismatch {
            in_did: in_did.to_owned(),
            derived,
        });
    }
    Ok(())
}

pub fn verify_log_subject(did: &str, log: &[WebvhLogEntry]) -> Result<(), WebvhValidationError> {
    for (at_index, entry) in log.iter().enumerate() {
        if entry.payload.pointer("/state/id").and_then(Value::as_str) != Some(did) {
            return Err(WebvhValidationError::MalformedEntry {
                at_index,
                reason: "state.id does not match the requested DID".to_owned(),
            });
        }
    }
    Ok(())
}

/// Reject every entry that declares a witness policy.
///
/// `did-freshness-profile-registry.json` registers no degraded read-only
/// profile, so there is no window inside which an unwitnessed entry may be
/// accepted: a declared witness policy with no verified witness signatures is
/// always a quorum failure.
pub fn validate_witness_policy_for_log(log: &[WebvhLogEntry]) -> Result<(), WebvhValidationError> {
    for (at_index, entry) in log.iter().enumerate() {
        let parameters = entry.payload.get("parameters").ok_or_else(|| {
            WebvhValidationError::MalformedEntry {
                at_index,
                reason: "parameters is required".to_owned(),
            }
        })?;
        match arkret_identity::parse_did_webvh_witness_policy(parameters) {
            Ok(None) => {}
            Ok(Some(policy)) => {
                return Err(WebvhValidationError::WitnessQuorumNotMet {
                    at_index,
                    required: policy.threshold,
                    valid: 0,
                });
            }
            Err(error) => {
                return Err(WebvhValidationError::MalformedEntry {
                    at_index,
                    reason: error.to_string(),
                });
            }
        }
    }
    Ok(())
}

pub fn validate_rotation_authorization_for_log(
    log: &[WebvhLogEntry],
) -> Result<(), WebvhValidationError> {
    verify_sdk_chain(log)
}

pub fn validate_active_controller_proof(entry: &WebvhLogEntry) -> Result<(), WebvhValidationError> {
    arkret_identity::verify_did_webvh_entry_controller_proofs(&entry.payload).map_err(|error| {
        WebvhValidationError::RotationNotAuthorized {
            at_index: 0,
            reason: error.to_string(),
        }
    })
}

pub fn active_update_verification_methods(entry: &WebvhLogEntry) -> Vec<String> {
    entry
        .payload
        .pointer("/parameters/updateKeys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|key| {
            let key = key.strip_prefix("did:key:").unwrap_or(key);
            format!("did:key:{key}#{key}")
        })
        .collect()
}

pub fn verify_webvh_log_proof(entry: &Value) -> Result<(), String> {
    arkret_identity::verify_did_webvh_entry_controller_proofs(entry)
        .map_err(|error| error.to_string())
}

pub(crate) fn webvh_entry_hash_multibase(
    entry: &Value,
    previous_anchor: &str,
) -> Result<String, String> {
    arkret_identity::did_webvh_entry_hash(entry, previous_anchor).map_err(|error| error.to_string())
}

pub(crate) fn decode_ed25519_public_key(value: &str) -> Result<VerifyingKey, String> {
    let key =
        arkret_canonical::decode_ed25519_multibase(value).map_err(|error| error.to_string())?;
    VerifyingKey::from_bytes(&key).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        WebvhLogEntry, WebvhValidationError, validate_log_chain, verify_log_and_witness_bytes,
    };

    #[test]
    fn residual_scid_placeholder_has_param_invalid_discriminator() {
        let log = [WebvhLogEntry::new(json!({
            "versionId": "1-zQmPublished",
            "versionTime": "2026-08-16T00:00:00Z",
            "parameters": {
                "method": "did:webvh:1.0",
                "scid": "zQmPublished",
                "updateKeys": ["z6MkFixture"]
            },
            "state": {
                "id": "did:webvh:zQmPublished:example.com:webvh:alice",
                "alsoKnownAs": ["literal {SCID} must be rejected"]
            }
        }))];

        let error = validate_log_chain(&log).expect_err("residual placeholder must fail closed");
        assert_eq!(error.code(), "param_invalid");
        assert_eq!(
            error,
            WebvhValidationError::ResidualScidPlaceholder { at_index: 0 }
        );
    }

    #[test]
    fn soland_adapter_accepts_standard_did_webvh_witness_documents() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/did-webvh-witness-official.json"
        ))
        .expect("official fixture must decode");
        let did = arkret_wire::DidFullId::new(
            fixture["did"]
                .as_str()
                .expect("official fixture contains the DID"),
        )
        .expect("official fixture DID is valid");
        let did_jsonl = fixture["did_log_entries"]
            .as_array()
            .expect("official fixture contains log entries")
            .iter()
            .map(|entry| serde_json::to_string(entry).expect("entry serializes"))
            .collect::<Vec<_>>()
            .join("\n");
        let did_witness_json =
            serde_json::to_vec(&fixture["did_witness_json"]).expect("witness file serializes");

        let verified = verify_log_and_witness_bytes(&did, did_jsonl.as_bytes(), &did_witness_json)
            .expect("Soland must consume the SDK verifier for standard witness documents");

        assert_eq!(verified.log.entries.len(), 1);
        assert_eq!(verified.witness_sets[0].threshold, 1);
        assert_eq!(verified.witness_sets[0].verified_witnesses.len(), 1);
    }

    #[test]
    fn arkret_observation_receipt_cannot_replace_method_witness_proof() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/did-webvh-witness-official.json"
        ))
        .expect("official fixture must decode");
        let did = arkret_wire::DidFullId::new(
            fixture["did"]
                .as_str()
                .expect("official fixture contains the DID"),
        )
        .expect("official fixture DID is valid");
        let did_jsonl = fixture["did_log_entries"]
            .as_array()
            .expect("official fixture contains log entries")
            .iter()
            .map(|entry| serde_json::to_string(entry).expect("entry serializes"))
            .collect::<Vec<_>>()
            .join("\n");
        let observation_only = serde_json::to_vec(&json!([{
            "schema": "ak.schema.did_webvh_witness_receipt.v1",
            "did": did,
            "version_id": fixture["did_witness_json"][0]["versionId"],
            "threshold_met": true
        }]))
        .expect("observation serializes");

        let error =
            verify_log_and_witness_bytes(&did, did_jsonl.as_bytes(), observation_only.as_slice())
                .expect_err("Arkret observation cannot replace did-witness.json proofs");
        assert!(matches!(
            error,
            super::WebvhValidationError::WitnessQuorumNotMet { .. }
                | super::WebvhValidationError::WitnessSignatureInvalid { .. }
        ));
    }
}
