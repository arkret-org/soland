//! Shared wire contract for the coauth → soland capability fanout S2S call
//! (`POST /_soland/root/authz/capability-fanout`,
//! `org.arkret.soland.root.authz.capability_fanout.submit`).
//!
//! This is a deployment-internal product contract (service-http-binding.md
//! §2.1.4(b)), not a spec operation, so the types live in `soland-contracts`
//! rather than the SDK registry surface — the same pattern the sodmin admin
//! seal DTOs already use. Both ends (soland handler, coauth producer) MUST
//! consume these definitions instead of hand-writing mirrors (SOL-DRY-03).

use arkret_identifiers::{Hash, RealmId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const CAPABILITY_FANOUT_KIND: &str = "org.arkret.coauth.collaboration_capability.fanout.v1";
pub const CAPABILITY_FANOUT_PROOF_KIND: &str =
    "org.arkret.coauth.collaboration_capability.proof.v1";
use serde_json::Value;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityFanoutProof {
    pub kind: String,
    pub alg: String,
    pub verification_method: String,
    pub event_digest: Hash,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    pub jws: String,
}

pub fn capability_fanout_proof_transcript(
    operation: &str,
    issuer_service_id: &str,
    event_kind: &str,
    event_id: &str,
    capability_grant_id: &str,
    realm_id: &str,
    unsigned_payload: &Value,
) -> Value {
    serde_json::json!({
        "kind": CAPABILITY_FANOUT_PROOF_KIND,
        "fanout_kind": CAPABILITY_FANOUT_KIND,
        "operation": operation,
        "issuer_service_id": issuer_service_id,
        "event_kind": event_kind,
        "event_id": event_id,
        "capability_grant_id": capability_grant_id,
        "realm_id": realm_id,
        "payload": unsigned_payload,
    })
}

/// Request body coauth POSTs to `/_soland/root/authz/capability-fanout`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityFanoutBody {
    /// Fixed envelope kind `org.arkret.coauth.collaboration_capability.fanout.v1`.
    pub kind: String,
    /// The coauth-side operation this fanout materializes (e.g. grant /
    /// revoke), echoed back in the response.
    pub operation: String,
    pub issuer_service_id: String,
    /// Durable event kind the fanout projects (grant / revoke event kind).
    pub event_kind: String,
    pub event_id: String,
    pub capability_grant_id: String,
    /// Realm used to construct the local projection operation. This remains
    /// outside the protocol payload so revoke payloads stay schema-canonical.
    pub realm_id: RealmId,
    /// The event payload to project; treated as an opaque canonical-JSON
    /// value at this boundary and validated by the receiving reducer.
    pub payload: Value,
    /// Deployment-private transport attestations over the complete event
    /// payload. These are distinct from protocol payload proofs.
    pub proofs: Vec<CapabilityFanoutProof>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principal_servers: Vec<Value>,
}

/// Response from the soland fanout handler.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityFanoutResponse {
    pub accepted: Vec<String>,
    pub duplicate: Vec<String>,
    pub event_id: String,
    pub capability_grant_id: String,
    pub operation: String,
    pub authz_state: CapabilityFanoutAuthzState,
}

/// Post-projection authorization state the fanout handler observed.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityFanoutAuthzState {
    pub projected: bool,
    pub effective: bool,
    pub revoked: bool,
    pub grant_present: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_proof_transcript_binds_security_relevant_envelope_fields() {
        let payload = serde_json::json!({
            "grant_id": "ak:grant:01970000-0000-7000-8000-000000000001",
            "grant_ref": "ak:grant:01970000-0000-7000-8000-000000000001",
        });
        let transcript = |operation: &str, issuer: &str, realm: &str| {
            capability_fanout_proof_transcript(
                operation,
                issuer,
                "ak.capability.revoke",
                "ak:event:01970000-0000-7000-8000-000000000002",
                "ak:grant:01970000-0000-7000-8000-000000000001",
                realm,
                &payload,
            )
        };
        let baseline = arkret_canonical::canonical_sha256(&transcript(
            "revoke",
            "did:web:coauth.example",
            "ak:realm:01970000-0000-7000-8000-000000000003",
        ))
        .unwrap();

        for changed in [
            transcript(
                "grant",
                "did:web:coauth.example",
                "ak:realm:01970000-0000-7000-8000-000000000003",
            ),
            transcript(
                "revoke",
                "did:web:other.example",
                "ak:realm:01970000-0000-7000-8000-000000000003",
            ),
            transcript(
                "revoke",
                "did:web:coauth.example",
                "ak:realm:01970000-0000-7000-8000-000000000004",
            ),
        ] {
            assert_ne!(
                arkret_canonical::canonical_sha256(&changed).unwrap(),
                baseline
            );
        }
    }
}
